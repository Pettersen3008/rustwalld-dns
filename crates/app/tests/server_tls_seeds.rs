//! Public packed corpus replay for pure server TLS configuration; no files or handshakes.
//! The fixture key is deliberately public test data; no real service may use it.
#![allow(clippy::unwrap_used)]

use rustwalld_dns::tls::from_pem;

macro_rules! seed {
    ($name:literal) => {
        include_bytes!(concat!("../../../fuzz/seeds/server_tls/", $name))
    };
}

/// Mirrors fuzz_targets/server_tls.rs: mode byte, certificate, first NUL NUL, key.
fn split(input: &[u8]) -> Option<(bool, &[u8], &[u8])> {
    let (&mode, data) = input.split_first()?;
    let offset = data.windows(2).position(|bytes| bytes == b"\0\0")?;
    Some((mode & 1 != 0, &data[..offset], &data[offset + 2..]))
}

fn alpn(input: &[u8]) -> Vec<Vec<u8>> {
    let (http, cert, key) = split(input).unwrap();
    from_pem(cert, key, http)
        .ok()
        .unwrap()
        .config()
        .alpn_protocols
        .clone()
}

fn error(input: &[u8]) -> Option<String> {
    let (http, cert, key) = split(input).unwrap();
    from_pem(cert, key, http).err()
}

fn pair() -> (Vec<u8>, Vec<u8>) {
    let (_, cert, key) = split(seed!("valid-dot.bin")).unwrap();
    (cert.to_vec(), key.to_vec())
}

#[test]
fn valid_seeds_select_alpn_from_the_mode_bit() {
    let dot = vec![b"dot".to_vec()];
    let http = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    assert_eq!(alpn(seed!("valid-dot.bin")), dot);
    assert_eq!(alpn(seed!("valid-http.bin")), http);
    assert_eq!(alpn(seed!("valid-http-high-mode.bin")), http);
}

#[test]
fn missing_separator_is_skipped_before_parsing() {
    assert!(split(seed!("invalid-no-separator.bin")).is_none());
}

#[test]
fn invalid_seeds_reach_the_intended_guards() {
    for (input, expected) in [
        (
            &seed!("invalid-empty-key.bin")[..],
            "TLS PEM input exceeds its size bounds",
        ),
        (
            &seed!("invalid-certificate-pem.bin")[..],
            "Invalid certificate PEM",
        ),
        (
            &seed!("invalid-no-certificate.bin")[..],
            "TLS certificate chain needs 1..8 certificates",
        ),
        (&seed!("invalid-key-pem.bin")[..], "Invalid private key PEM"),
        (
            &seed!("invalid-key-is-certificate.bin")[..],
            "Invalid private key PEM",
        ),
        (
            &seed!("invalid-mismatch.bin")[..],
            "Invalid or mismatched TLS certificate/key",
        ),
    ] {
        assert!(input.len() <= 8192);
        assert_eq!(error(input).as_deref(), Some(expected));
    }
}

#[test]
fn chain_accepts_eight_certificates_before_refusing_nine() {
    let (cert, key) = pair();
    assert!(from_pem(&cert.repeat(8), &key, false).is_ok());
    assert_eq!(
        from_pem(&cert.repeat(9), &key, false).err().as_deref(),
        Some("TLS certificate chain needs 1..8 certificates")
    );
}

#[test]
fn exact_size_bounds_accept_padded_pem_before_refusing_one_extra_byte() {
    const BOUNDS: Option<&str> = Some("TLS PEM input exceeds its size bounds");
    let (mut cert, mut key) = pair();
    assert_eq!(from_pem(b"", &key, false).err().as_deref(), BOUNDS);
    cert.resize(256 * 1024, b'\n');
    key.resize(16 * 1024, b'\n');
    let mut packed = vec![1];
    packed.extend_from_slice(&cert);
    packed.extend_from_slice(b"\0\0");
    packed.extend_from_slice(&key);
    assert_eq!(packed.len(), 278_531);
    assert_eq!(alpn(&packed), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

    let mut long_cert = cert.clone();
    long_cert.push(b'\n');
    assert_eq!(from_pem(&long_cert, &key, false).err().as_deref(), BOUNDS);
    key.push(b'\n');
    assert_eq!(from_pem(&cert, &key, false).err().as_deref(), BOUNDS);
}
