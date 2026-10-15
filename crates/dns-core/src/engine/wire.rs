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
    let mut encoder = BinEncoder::new(&mut output);
    encoder.set_max_size(max);
    response.emit(&mut encoder).ok()?;
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
