#![no_main]
use hickory_proto::op::Message;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 9 || data.len() > 65544 {
        return;
    }
    // Stable question makes seed responses exercise the complete TTL/validation path.
    let wire = b"\0\0\x01\0\0\x01\0\0\0\0\0\0\x04fuzz\x04test\0\0\x01\0\x01";
    let Ok(query) = Message::from_vec(wire) else {
        return;
    };
    let flags = data[0];
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if flags & 1 != 0 {
            "application/json"
        } else {
            "application/dns-message"
        }),
    );
    if flags & 2 != 0 {
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/dns-message"),
        );
    }
    if flags & 4 != 0 {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    let age = if flags & 8 != 0 {
        HeaderValue::from_bytes(&data[1..9])
    } else {
        HeaderValue::from_str(&u32::from_le_bytes([data[1], data[2], data[3], data[4]]).to_string())
    };
    if let Ok(age) = age {
        headers.insert(header::AGE, age);
    }
    if flags & 16 != 0 {
        if let Ok(value) = HeaderValue::from_bytes(&data[1..9]) {
            headers.insert(header::CONTENT_LENGTH, value);
        }
    }
    let status = if flags & 32 != 0 {
        StatusCode::FOUND
    } else {
        StatusCode::OK
    };
    let _ = rustwalld_dns_resolver::https::decode_response(&query, status, &headers, &data[9..]);
});
