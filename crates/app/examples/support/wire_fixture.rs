//! Fixed lab references and explicit private IPv4 binding for the comparative fixture.
use super::{Result, invalid, mock_answer, query};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{DNSClass, RData, Record, RecordType, rdata::A},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use rustwalld_dns_core::reply;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
    time::timeout,
};

pub fn listen_address(text: &str) -> std::result::Result<SocketAddrV4, String> {
    let address: SocketAddrV4 = text.parse().map_err(|_| {
        "listen must be a numeric private or loopback IPv4 socket address".to_owned()
    })?;
    if address.port() == 0 || !(address.ip().is_private() || address.ip().is_loopback()) {
        return Err("listen requires a private or loopback IPv4 address and nonzero port".into());
    }
    Ok(address)
}

pub fn bind_address(text: &str) -> std::result::Result<Ipv4Addr, String> {
    let address: Ipv4Addr = text
        .parse()
        .map_err(|_| "bind must be a numeric private or loopback IPv4 address".to_owned())?;
    if !address.is_private() && !address.is_loopback() {
        return Err("bind requires a private or loopback IPv4 address".into());
    }
    Ok(address)
}

fn complete_message(bytes: &[u8]) -> Result<Message> {
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder)?;
    if decoder.index() != bytes.len() {
        return Err(invalid("trailing DNS reply bytes").into());
    }
    Ok(message)
}

fn bounded_udp(request: &Message, response: &Message) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let committed = {
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(request.max_payload().clamp(512, 1232));
        response.emit(&mut encoder)?;
        encoder.offset()
    };
    // Hickory may rewind its cursor without shrinking the backing Vec.
    bytes.truncate(committed);
    Ok(bytes)
}

/// Observe downstream truncation before making an independent complete TCP query.
pub async fn probe_large(endpoint: SocketAddrV4, bind: Ipv4Addr) -> Result<Value> {
    let request = query("large.bench.test.", RecordType::A, 0x4c47)?;
    let bytes = request.to_vec()?;
    let mut buffer = vec![0; 65535];
    let n = timeout(Duration::from_secs(2), async {
        let socket = UdpSocket::bind(SocketAddrV4::new(bind, 0)).await?;
        socket.connect(endpoint).await?;
        socket.send(&bytes).await?;
        socket.recv(&mut buffer).await
    })
    .await??;
    let udp = complete_message(&buffer[..n])?;
    let mut expected_header = reply(&request, ResponseCode::NoError).metadata;
    expected_header.truncation = true;
    if n > 512 || udp.metadata != expected_header || udp.queries != request.queries {
        return Err(
            invalid("large legacy UDP reply must be bounded, correct and truncated").into(),
        );
    }
    let tcp_n = timeout(Duration::from_secs(2), async {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::V4(SocketAddrV4::new(bind, 0)))?;
        let mut stream = socket.connect(endpoint.into()).await?;
        stream.set_nodelay(true)?;
        stream.write_u16(bytes.len() as u16).await?;
        stream.write_all(&bytes).await?;
        let n = usize::from(stream.read_u16().await?);
        if n < 12 {
            return Err(invalid("short large TCP reply"));
        }
        stream.read_exact(&mut buffer[..n]).await?;
        Ok(n)
    })
    .await??;
    let tcp = complete_message(&buffer[..tcp_n])?;
    if tcp.metadata != reply(&request, ResponseCode::NoError).metadata {
        return Err(invalid("large TCP reply header mismatch").into());
    }
    super::validate(&request, &tcp)?;
    Ok(json!({"passed":true,"endpoint":endpoint,"bind":bind,
        "udp_bytes":n,"udp_truncated":true,"udp_answers":udp.answers.len(),
        "tcp_bytes":tcp_n,"tcp_answers":tcp.answers.len()}))
}

/// Fits the resolver's fresh 1232-byte envelope, but exceeds legacy client UDP.
pub fn large_answer(request: &Message, tcp: bool, corrupt: bool) -> Result<Message> {
    let question = request
        .queries
        .first()
        .ok_or_else(|| invalid("large fixture requires one A question"))?;
    if question.query_type() != RecordType::A {
        return Err(invalid("large fixture requires an A question").into());
    }
    let mut response = reply(request, ResponseCode::NoError);
    for last in 1..=64 {
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(A::new(
                192,
                0,
                2,
                if corrupt && last == 1 { 99 } else { last },
            )),
        ));
    }
    if tcp {
        return Ok(response);
    }
    complete_message(&bounded_udp(request, &response)?)
}

/// Check the independently fixed address set, including duplicate/missing data.
pub fn validate_large(request: &Message, response: &Message) -> Result<()> {
    let question = request
        .queries
        .first()
        .ok_or_else(|| invalid("large fixture requires one A question"))?;
    if question.query_type() != RecordType::A
        || response.answers.len() != 64
        || !response.authorities.is_empty()
        || !response.additionals.is_empty()
        || response.signature.is_some()
    {
        return Err(invalid("large answer has incorrect question or record set").into());
    }
    let mut seen = [false; 64];
    for record in &response.answers {
        let RData::A(address) = &record.data else {
            return Err(invalid("large answer contains a non-A record").into());
        };
        let [a, b, c, last] = address.0.octets();
        if record.name != *question.name()
            || record.dns_class != DNSClass::IN
            || record.ttl > 300
            || [a, b, c] != [192, 0, 2]
            || !(1..=64).contains(&last)
            || std::mem::replace(&mut seen[usize::from(last.saturating_sub(1))], true)
        {
            return Err(
                invalid("large answer contains an incorrect address/owner/class/TTL").into(),
            );
        }
    }
    Ok(())
}

pub fn references() -> Result<BTreeMap<&'static str, String>> {
    let mut output = BTreeMap::new();
    for (key, name, kind) in [
        ("cache", "cache.bench.test.", RecordType::A),
        ("ipv6", "ipv6.bench.test.", RecordType::AAAA),
        ("alias", "alias.bench.test.", RecordType::A),
        ("nx-cache", "nx-cache.bench.test.", RecordType::A),
        ("nodata", "nodata-cache.bench.test.", RecordType::A),
        ("truncate", "truncate.bench.test.", RecordType::A),
        ("large", "large.bench.test.", RecordType::A),
        (
            "allowed.suffix",
            "allowed.suffix.bench.test.",
            RecordType::A,
        ),
        ("fresh", "cold-0-0.bench.test.", RecordType::A),
        (
            "blocked.suffix",
            "blocked.suffix.bench.test.",
            RecordType::A,
        ),
        ("local.soak.test", "local.soak.test.", RecordType::A),
    ] {
        let request = query(name, kind, 0)?;
        let response = if key == "blocked.suffix" {
            reply(&request, ResponseCode::NXDomain)
        } else if key == "local.soak.test" {
            let mut response = reply(&request, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A("192.0.2.1".parse()?)),
            ));
            response
        } else {
            // The complete TCP answer is the oracle after upstream UDP truncation.
            mock_answer(&request, true, false)?
        };
        let bytes = response.to_vec()?;
        if bytes.len() > 4096 {
            return Err(invalid("fixture reference exceeds the driver packet bound").into());
        }
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(encoded, "{byte:02x}")?;
        }
        output.insert(key, encoded);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::super::{Args, Command, validate};
    use super::*;
    use clap::Parser;
    use hickory_proto::op::{Edns, Message, MessageType};

    fn decode(text: &str) -> Message {
        let bytes: Vec<_> = text
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        Message::from_vec(&bytes).unwrap()
    }

    #[test]
    fn serve_cli_preserves_default_and_accepts_explicit_private_ipv4() {
        let Command::Serve { listen, .. } = Args::try_parse_from(["wire_compare", "serve"])
            .unwrap()
            .command
        else {
            panic!("expected serve");
        };
        assert_eq!(listen, "127.0.0.1:1053".parse().unwrap());
        for address in ["10.1.2.3:1053", "172.30.77.20:1053", "192.168.4.2:65535"] {
            let Command::Serve { listen, .. } =
                Args::try_parse_from(["wire_compare", "serve", "--listen", address])
                    .unwrap()
                    .command
            else {
                panic!("expected serve");
            };
            assert_eq!(listen.to_string(), address);
        }
        assert!(matches!(
            Args::try_parse_from(["wire_compare", "references"])
                .unwrap()
                .command,
            Command::References
        ));
    }

    #[test]
    fn serve_cli_rejects_public_wildcard_multicast_ipv6_and_zero_port() {
        for address in [
            "0.0.0.0:1053",
            "8.8.8.8:1053",
            "224.0.0.1:1053",
            "255.255.255.255:1053",
            "169.254.1.2:1053",
            "127.0.0.1:0",
            "10.0.0.1:0",
            "[::1]:1053",
            "[fd00::1]:1053",
            "localhost:1053",
        ] {
            assert!(
                Args::try_parse_from(["wire_compare", "serve", "--listen", address]).is_err(),
                "accepted {address}"
            );
        }
    }

    #[test]
    fn probe_cli_accepts_only_numeric_private_or_loopback_addresses() {
        assert!(matches!(
            Args::try_parse_from([
                "wire_compare",
                "probe-large",
                "--endpoint",
                "172.30.77.10:5353",
                "--bind",
                "172.30.77.20",
            ])
            .unwrap()
            .command,
            Command::ProbeLarge { .. }
        ));
        for (flag, invalid) in [
            ("--endpoint", "8.8.8.8:53"),
            ("--endpoint", "0.0.0.0:5353"),
            ("--endpoint", "127.0.0.1:0"),
            ("--endpoint", "[::1]:5353"),
            ("--endpoint", "localhost:5353"),
            ("--bind", "8.8.8.8"),
            ("--bind", "0.0.0.0"),
            ("--bind", "224.0.0.1"),
            ("--bind", "169.254.1.1"),
            ("--bind", "::1"),
            ("--bind", "localhost"),
        ] {
            let mut args = vec![
                "wire_compare",
                "probe-large",
                "--endpoint",
                "127.0.0.1:5353",
                "--bind",
                "127.0.0.1",
            ];
            args[if flag == "--endpoint" { 3 } else { 5 }] = invalid;
            assert!(
                Args::try_parse_from(args).is_err(),
                "accepted {flag} {invalid}"
            );
        }
    }

    #[test]
    fn probe_decoder_requires_one_complete_hickory_message() {
        let request = query("large.bench.test.", RecordType::A, 71).unwrap();
        let mut bytes = mock_answer(&request, true, false)
            .unwrap()
            .to_vec()
            .unwrap();
        assert!(complete_message(&bytes).is_ok());
        bytes.push(0);
        assert!(complete_message(&bytes).is_err());
        assert!(complete_message(&bytes[..11]).is_err());
    }

    #[test]
    fn large_answer_exceeds_legacy_udp_and_fits_fresh_upstream_envelope() {
        let request = query("large.bench.test.", RecordType::A, 73).unwrap();
        let full = mock_answer(&request, true, false).unwrap();
        let size = full.to_vec().unwrap().len();
        assert!(size > 512 && size < 1232, "large answer is {size} bytes");
        assert!(!full.metadata.truncation);
        validate(&request, &full).unwrap();

        let raw_udp = bounded_udp(&request, &full).unwrap();
        assert!(raw_udp.len() <= 512);
        let raw_message = complete_message(&raw_udp).unwrap();
        assert!(raw_message.metadata.truncation);
        assert!(raw_message.answers.len() < 64);
        let legacy = mock_answer(&request, false, false).unwrap();
        assert!(legacy.to_vec().unwrap().len() <= 512);
        assert!(legacy.metadata.truncation);
        assert_eq!(legacy.queries, request.queries);
        assert!(legacy.answers.len() < 64);
        assert!(validate(&request, &legacy).is_err());

        let mut upstream = request.clone();
        upstream.set_edns(Edns::new().set_max_payload(1232).clone());
        let complete_udp = mock_answer(&upstream, false, false).unwrap();
        assert!(!complete_udp.metadata.truncation);
        assert!(complete_udp.to_vec().unwrap().len() <= 1232);
        validate(&upstream, &complete_udp).unwrap();
        assert_eq!(complete_udp.answers, full.answers);
    }

    #[test]
    fn large_oracle_requires_exact_addresses_owners_classes_ttls_and_sections() {
        let request = query("large.bench.test.", RecordType::A, 79).unwrap();
        let full = mock_answer(&request, true, false).unwrap();
        assert!(validate(&request, &mock_answer(&request, true, true).unwrap()).is_err());
        for mutation in 0..9 {
            let mut wrong = full.clone();
            match mutation {
                0 => {
                    wrong.answers.pop();
                }
                1 => wrong.answers.push(wrong.answers[0].clone()),
                2 => wrong.answers[0] = wrong.answers[1].clone(),
                3 => {
                    wrong.answers[0].name =
                        hickory_proto::rr::Name::from_ascii("other.bench.test.").unwrap()
                }
                4 => wrong.answers[0].ttl = 301,
                5 => wrong.answers[0].dns_class = DNSClass::CH,
                6 => {
                    wrong.answers[0].data = RData::AAAA(hickory_proto::rr::rdata::AAAA(
                        "2001:db8::1".parse().unwrap(),
                    ))
                }
                7 => wrong.authorities.push(wrong.answers[0].clone()),
                _ => wrong.additionals.push(wrong.answers[0].clone()),
            }
            assert!(
                validate(&request, &wrong).is_err(),
                "accepted mutation {mutation}"
            );
        }
        let mut reordered = full;
        reordered.answers.reverse();
        for record in &mut reordered.answers {
            record.ttl = 0;
        }
        validate(&request, &reordered).unwrap();
        let wrong_type = query("large.bench.test.", RecordType::AAAA, 79).unwrap();
        assert!(mock_answer(&wrong_type, true, false).is_err());
        assert!(validate(&wrong_type, &reordered).is_err());
    }

    #[test]
    fn fixed_references_are_complete_valid_hickory_answers() {
        let references = references().unwrap();
        assert_eq!(references.len(), 11);
        for hex in references.values() {
            assert!(hex.len() <= 8192 && hex.len().is_multiple_of(2));
            let answer = decode(hex);
            assert_eq!(answer.metadata.message_type, MessageType::Response);
            assert!(!answer.metadata.truncation);
            assert!(answer.metadata.recursion_desired);
            assert_eq!(answer.queries.len(), 1);
            assert!(answer.queries[0].name().to_ascii().ends_with(".test."));
            let request = query(
                &answer.queries[0].name().to_ascii(),
                answer.queries[0].query_type(),
                answer.metadata.id,
            )
            .unwrap();
            validate(&request, &answer).unwrap();
        }
        let blocked = decode(&references["blocked.suffix"]);
        assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
        assert!(blocked.answers.is_empty() && blocked.authorities.is_empty());
        let local = decode(&references["local.soak.test"]);
        assert_eq!(local.answers.len(), 1);
        assert_eq!(local.answers[0].ttl, 60);
        assert_eq!(local.answers[0].name.to_ascii(), "local.soak.test.");
        assert_eq!(
            local.answers[0].data,
            RData::A(A("192.0.2.1".parse().unwrap()))
        );
        assert_eq!(decode(&references["alias"]).answers.len(), 2);
        assert_eq!(
            decode(&references["fresh"]).queries[0].name().to_ascii(),
            "cold-0-0.bench.test."
        );
        assert_eq!(
            decode(&references["ipv6"]).queries[0].query_type(),
            RecordType::AAAA
        );
        for (key, code) in [
            ("nx-cache", ResponseCode::NXDomain),
            ("nodata", ResponseCode::NoError),
        ] {
            let answer = decode(&references[key]);
            assert_eq!(answer.metadata.response_code, code);
            assert!(answer.answers.is_empty());
            assert_eq!(answer.authorities.len(), 1);
        }
    }
}
