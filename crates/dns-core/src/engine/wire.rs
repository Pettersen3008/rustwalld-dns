use super::Transport;
use hickory_proto::{
    op::{Edns, Message, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};

/// The single question of a query this engine serves, or the reply code that
/// refuses it. EDNS options are ignored as RFC 6891 requires: none are
/// forwarded (upstream requests carry a fresh EDNS envelope), so they cannot
/// alter cached content.
pub(super) fn accepted_question(request: &Message) -> Result<&Query, ResponseCode> {
    if request.metadata.op_code != OpCode::Query {
        return Err(ResponseCode::NotImp);
    }
    let [question] = request.queries.as_slice() else {
        return Err(ResponseCode::FormErr);
    };
    if !request.metadata.recursion_desired
        || question.query_class() != DNSClass::IN
        || matches!(
            question.query_type(),
            RecordType::AXFR | RecordType::IXFR | RecordType::ANY
        )
        || request.signature.is_some()
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || !request.additionals.is_empty()
    {
        return Err(ResponseCode::Refused);
    }
    if request.version() != 0 {
        return Err(ResponseCode::BADVERS);
    }
    Ok(question)
}

/// Restore the client's ID, flags, question and EDNS envelope on a reply that
/// may come from a shared cache entry or coalesced flight.
pub(super) fn finalize(request: &Message, response: &mut Message) {
    response.metadata.id = request.metadata.id;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    response.metadata.authentic_data = false;
    if request.queries.len() == 1 {
        response.queries.clone_from(&request.queries);
    }
    response.edns = request.edns.as_ref().map(|edns| {
        let mut out = Edns::new();
        out.set_max_payload(edns.max_payload().clamp(512, 1232));
        out.set_dnssec_ok(edns.flags().dnssec_ok);
        out
    });
}

/// Wire-encode a reply within the transport's size limit; UDP replies that do
/// not fit are truncated with TC set.
pub(super) fn encode(
    request: &Message,
    response: &Message,
    transport: Transport,
) -> Option<Vec<u8>> {
    let max = match transport {
        Transport::Tcp => u16::MAX,
        Transport::Udp => request.max_payload().clamp(512, 1232),
    };
    let mut output = Vec::with_capacity(512);
    let committed = {
        let mut encoder = BinEncoder::new(&mut output);
        encoder.set_max_size(max);
        response.emit(&mut encoder).ok()?;
        encoder.offset()
    };
    // Hickory rolls back an incomplete record's cursor, retaining its Vec bytes.
    output.truncate(committed);
    Some(output)
}

pub(super) fn canonical_ascii(name: &Name) -> String {
    // Hickory emits ASCII letters literally, and other bytes as escaped
    // punctuation or octal digits. Lowercasing the output therefore preserves
    // its label boundaries and escapes without copying the intermediate Name.
    let mut ascii = name.to_ascii();
    ascii.make_ascii_lowercase();
    ascii
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hickory_proto::{
        rr::{
            RData, Record,
            rdata::{A, AAAA},
        },
        serialize::binary::{BinDecodable, BinDecoder},
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn encoded_transport_limits_end_at_complete_record_boundaries() {
        for count in [1, 64, 128] {
            for ipv6 in [false, true] {
                for (transport, payload) in [
                    (Transport::Udp, None),
                    (Transport::Udp, Some(1232)),
                    (Transport::Tcp, None),
                ] {
                    let mut request = Message::query();
                    request.metadata.id = 0x3131;
                    request.metadata.recursion_desired = true;
                    let name = Name::from_ascii("large-wire.test.").unwrap();
                    request.add_query(Query::query(
                        name.clone(),
                        if ipv6 {
                            RecordType::AAAA
                        } else {
                            RecordType::A
                        },
                    ));
                    if let Some(payload) = payload {
                        let mut edns = Edns::new();
                        edns.set_max_payload(payload);
                        request.edns = Some(edns);
                    }
                    let mut response = crate::reply(&request, ResponseCode::NoError);
                    for index in 0..count {
                        let data = if ipv6 {
                            RData::AAAA(AAAA(Ipv6Addr::new(
                                0x2001,
                                0xdb8,
                                0,
                                0,
                                0,
                                0,
                                0,
                                u16::from(index),
                            )))
                        } else {
                            RData::A(A(Ipv4Addr::new(192, 0, 2, index)))
                        };
                        response.add_answer(Record::from_rdata(name.clone(), 300, data));
                    }
                    finalize(&request, &mut response);
                    let limit = match transport {
                        Transport::Tcp => usize::from(u16::MAX),
                        Transport::Udp => usize::from(payload.unwrap_or(512)),
                    };
                    let complete = response.to_vec().unwrap();
                    let bytes = encode(&request, &response, transport).unwrap();
                    assert!(bytes.len() <= limit);
                    let mut decoder = BinDecoder::new(&bytes);
                    let decoded = Message::read(&mut decoder).unwrap();
                    assert!(
                        decoder.is_empty(),
                        "unparsed suffix: {} bytes, count={count}, ipv6={ipv6}, payload={payload:?}",
                        decoder.len()
                    );
                    assert_eq!(decoded.metadata.id, request.metadata.id);
                    assert_eq!(decoded.queries, request.queries);
                    assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
                    assert_eq!(decoded.metadata.truncation, complete.len() > limit);
                    let written = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
                    assert_eq!(written, decoded.answers.len());
                    assert_eq!(decoded.answers, response.answers[..written]);
                    if complete.len() <= limit {
                        assert_eq!(decoded.answers.len(), usize::from(count));
                        assert_eq!(bytes, complete);
                    } else {
                        assert!(written > 0 && written < usize::from(count));
                    }
                }
            }
        }
    }

    #[test]
    fn canonical_ascii_preserves_hickory_escaping_and_case_semantics() {
        let check = |mut name: Name| {
            for fqdn in [true, false] {
                name.set_fqdn(fqdn);
                assert_eq!(canonical_ascii(&name), name.to_lowercase().to_ascii());
            }
        };
        check(Name::root());
        // Every byte at the start, middle and end of a label, including dots,
        // backslashes, controls, wildcard characters and non-ASCII wire bytes.
        for byte in 0..=u8::MAX {
            for label in [[byte, b'A', b'Z'], [b'A', byte, b'Z'], [b'A', b'Z', byte]] {
                check(Name::from_labels([label.as_slice(), b"ExAmPlE".as_slice()]).unwrap());
            }
            let labels = [
                vec![byte; 63],
                vec![b'A'; 63],
                vec![b'Z'; 63],
                vec![b'B'; 61],
            ];
            check(Name::from_labels(labels.iter().map(Vec::as_slice)).unwrap());
        }
        check(Name::from_labels(std::iter::repeat_n(b"A".as_slice(), 127)).unwrap());
    }
}
