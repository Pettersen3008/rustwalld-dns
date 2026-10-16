//! Public synthetic corpus replay for pure identity validation; no hashing or file IO.
//! Every PHC, TOTP and digest value is dummy public data, never a usable credential.
#![allow(clippy::unwrap_used)]

use rustwalld_dns::auth::validate_document;

macro_rules! seed {
    ($name:literal) => {
        include_bytes!(concat!("../../../fuzz/seeds/identity/", $name))
    };
}

const PHC: &str = "$argon2id$v=19$m=32768,t=3,p=1$AAECAwQFBgcICQoLDA0ODw$ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn document(name: &str, password_hash: &str, totp: &str, tokens: usize) -> String {
    let tokens: Vec<String> = (0..tokens)
        .map(|index| {
            format!(r#"{{"id":"{index:032x}","name":"t{index}","role":"operator","expires_at":1,"digest":"{DIGEST}"}}"#)
        })
        .collect();
    format!(
        r#"{{"schema":1,"revision":1,"user":{{"name":"{name}","password_hash":"{password_hash}","totp_secret":{totp},"last_totp_step":null}},"tokens":[{}]}}"#,
        tokens.join(",")
    )
}

fn error(input: &[u8]) -> Option<String> {
    validate_document(input).err()
}

#[test]
fn valid_seeds_reach_successful_validation() {
    for input in [
        &seed!("valid-minimal.json")[..],
        &seed!("valid-totp-tokens.json")[..],
    ] {
        assert!(input.len() <= 4096);
        assert_eq!(error(input), None);
    }
}

#[test]
fn invalid_seeds_reach_the_intended_guards() {
    const JSON: &str = "Invalid credential JSON";
    const HEADER: &str = "Invalid credential schema, revision, username or token count";
    const TOKEN: &str = "Invalid or duplicate scoped token";
    for (input, expected) in [
        (&seed!("invalid-truncated.json")[..], JSON),
        (&seed!("invalid-unknown-field.json")[..], JSON),
        (&seed!("invalid-role.json")[..], JSON),
        (&seed!("invalid-schema.json")[..], HEADER),
        (&seed!("invalid-revision-zero.json")[..], HEADER),
        (&seed!("invalid-name-control.json")[..], HEADER),
        (
            &seed!("invalid-phc-params.json")[..],
            "Credential hash needs fixed Argon2id v19 parameters",
        ),
        (
            &seed!("invalid-phc-salt.json")[..],
            "Credential hash requires a 16-byte salt and 32-byte output",
        ),
        (
            &seed!("invalid-replay-without-totp.json")[..],
            "Replay counter requires TOTP",
        ),
        (
            &seed!("invalid-totp-short.json")[..],
            "TOTP secret requires 20..64 bytes",
        ),
        (&seed!("invalid-duplicate-token.json")[..], TOKEN),
        (&seed!("invalid-token-uppercase.json")[..], TOKEN),
        (&seed!("invalid-expiry.json")[..], TOKEN),
    ] {
        assert!(input.len() <= 4096);
        assert_eq!(error(input).as_deref(), Some(expected));
    }
}

#[test]
fn phc_shape_requires_exact_decoded_salt_and_output_lengths() {
    let short_output = PHC.replace("Pj8", "Pg");
    let malformed = PHC.replace("$ICEi", "$!CEi");
    assert_eq!(error(document("a", PHC, "null", 0).as_bytes()), None);
    assert_eq!(
        error(document("a", &short_output, "null", 0).as_bytes()).as_deref(),
        Some("Credential hash requires a 16-byte salt and 32-byte output")
    );
    assert_eq!(
        error(document("a", &malformed, "null", 0).as_bytes()).as_deref(),
        Some("Invalid credential hash")
    );
}

#[test]
fn totp_secret_accepts_20_to_64_decoded_bytes_only() {
    let secret_64 = "\"AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T4PY\"";
    let secret_65 = "\"AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T4P2A\"";
    assert_eq!(error(document("a", PHC, secret_64, 0).as_bytes()), None);
    assert_eq!(
        error(document("a", PHC, secret_65, 0).as_bytes()).as_deref(),
        Some("TOTP secret requires 20..64 bytes")
    );
    assert_eq!(
        error(document("a", PHC, "\"aaaqeaye\"", 0).as_bytes()).as_deref(),
        Some("Invalid TOTP provisioning secret")
    );
}

#[test]
fn label_token_and_expiry_bounds_are_exact() {
    const HEADER: &str = "Invalid credential schema, revision, username or token count";
    assert_eq!(
        error(document(&"x".repeat(128), PHC, "null", 0).as_bytes()),
        None
    );
    assert_eq!(
        error(document(&"x".repeat(129), PHC, "null", 0).as_bytes()).as_deref(),
        Some(HEADER)
    );
    assert_eq!(error(document("a", PHC, "null", 64).as_bytes()), None);
    assert_eq!(
        error(document("a", PHC, "null", 65).as_bytes()).as_deref(),
        Some(HEADER)
    );
    assert_eq!(
        error(document("", PHC, "null", 0).as_bytes()).as_deref(),
        Some(HEADER)
    );
    let valid = document("a", PHC, "null", 1);
    for invalid in [
        valid.replace("\"expires_at\":1", "\"expires_at\":0"),
        valid.replace(DIGEST, &DIGEST.to_ascii_uppercase()),
    ] {
        assert_eq!(
            error(invalid.as_bytes()).as_deref(),
            Some("Invalid or duplicate scoped token")
        );
    }
}

#[test]
fn exact_byte_limit_accepts_padded_document_before_refusing_one_extra_byte() {
    let mut text = document("a", PHC, "null", 1);
    text.extend(std::iter::repeat_n(' ', 65536 - text.len()));
    assert_eq!(text.len(), 65536);
    assert_eq!(error(text.as_bytes()), None);
    text.push(' ');
    assert_eq!(
        error(text.as_bytes()).as_deref(),
        Some("Credential file exceeds 64 KiB")
    );
}
