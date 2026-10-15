//! Fixed lab references and explicit private IPv4 binding for the comparative fixture.
use super::{Result, invalid, mock_answer, query};
use hickory_proto::{
    op::ResponseCode,
    rr::{RData, Record, RecordType, rdata::A},
};
use rustwalld_dns_core::reply;
use std::{collections::BTreeMap, fmt::Write, net::SocketAddrV4};

pub fn listen_address(text: &str) -> std::result::Result<SocketAddrV4, String> {
    let address: SocketAddrV4 = text.parse().map_err(|_| {
        "listen must be a numeric private or loopback IPv4 socket address".to_owned()
    })?;
    if address.port() == 0 || !(address.ip().is_private() || address.ip().is_loopback()) {
        return Err("listen requires a private or loopback IPv4 address and nonzero port".into());
    }
    Ok(address)
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
    use hickory_proto::op::{Message, MessageType};

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
    fn fixed_references_are_complete_valid_hickory_answers() {
        let references = references().unwrap();
        assert_eq!(references.len(), 10);
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
