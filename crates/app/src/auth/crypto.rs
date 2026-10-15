//! Fixed-cost password hashing and standard TOTP. No network or policy state.
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
pub(super) fn hash_token(bytes: &[u8]) -> [u8; 32] {
    let value = digest::digest(&digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(value.as_ref());
    out
}
pub(super) fn nonce() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "Secure randomness unavailable")?;
    Ok(data_encoding::HEXLOWER.encode(&bytes))
}
fn argon() -> Result<Argon2<'static>, String> {
    let params =
        Params::new(32768, 3, 1, Some(32)).map_err(|_| "Invalid password cost parameters")?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}
pub(super) fn validate_hash(input: &str) -> Result<(), String> {
    if input.len() > 256 || !input.starts_with("$argon2id$v=19$m=32768,t=3,p=1$") {
        return Err("Credential hash needs fixed Argon2id v19 parameters".into());
    }
    let parsed = PasswordHash::new(input).map_err(|_| "Invalid credential hash")?;
    if parsed.salt.as_ref().is_none_or(|salt| salt.len() != 16)
        || parsed.hash.as_ref().is_none_or(|hash| hash.len() != 32)
    {
        return Err("Credential hash requires a 16-byte salt and 32-byte output".into());
    }
    Ok(())
}
pub fn password_hash(password: &[u8]) -> Result<String, String> {
    if !(12..=1024).contains(&password.len()) {
        return Err("Password must contain 12..1024 bytes".into());
    }
    let mut salt = [0u8; 16];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| "Secure randomness unavailable")?;
    argon()?
        .hash_password_with_salt(password, &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "Password hashing failed".into())
}
pub(super) fn password_valid(password: &[u8], hash: &str) -> bool {
    if password.len() > 1024 || validate_hash(hash).is_err() {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    argon().is_ok_and(|argon| argon.verify_password(password, &parsed).is_ok())
}
pub(super) fn totp_secret() -> Result<Zeroizing<String>, String> {
    let mut bytes = [0u8; 20];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "Secure randomness unavailable")?;
    Ok(Zeroizing::new(data_encoding::BASE32_NOPAD.encode(&bytes)))
}
pub(super) fn decode_secret(value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let bytes = data_encoding::BASE32_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| "Invalid TOTP provisioning secret")?;
    if !(20..=64).contains(&bytes.len()) {
        return Err("TOTP secret requires 20..64 bytes".into());
    }
    Ok(Zeroizing::new(bytes))
}
pub(super) fn code(secret: &[u8], step: u64, digits: u32) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let signed = hmac::sign(&key, &step.to_be_bytes());
    let bytes = signed.as_ref();
    let offset = usize::from(bytes[19] & 15);
    let number = u32::from_be_bytes([
        bytes[offset] & 0x7f,
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]) % 10u32.pow(digits);
    format!("{number:0width$}", width = digits as usize)
}
pub(super) fn totp_step(
    secret: &[u8],
    input: &str,
    seconds: u64,
    last: Option<u64>,
) -> Option<u64> {
    if input.len() != 6 || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let step = seconds / 30;
    let mut matched = None;
    for candidate in [step.checked_sub(1), Some(step), step.checked_add(1)]
        .into_iter()
        .flatten()
    {
        let valid = bool::from(
            code(secret, candidate, 6)
                .as_bytes()
                .ct_eq(input.as_bytes()),
        );
        if valid && last.is_none_or(|last| candidate > last) {
            matched = Some(candidate);
        }
    }
    matched
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn standard_totp_vectors_windows_and_replay() {
        let secret = b"12345678901234567890";
        for (seconds, want) in [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(code(secret, seconds / 30, 8), want);
        }
        let current = code(secret, 100, 6);
        assert_eq!(totp_step(secret, &current, 3000, None), Some(100));
        assert_eq!(totp_step(secret, &current, 3030, None), Some(100));
        assert_eq!(totp_step(secret, &current, 3060, None), None);
        assert_eq!(totp_step(secret, &current, 3000, Some(100)), None);
        assert_eq!(totp_step(secret, &current, 2970, Some(100)), None);
        assert_eq!(totp_step(secret, "123", 3000, None), None);
    }
    #[test]
    fn password_cost_is_fixed_and_malformed_hashes_cannot_expand_work() {
        let hash = password_hash(b"fixture-password-16").unwrap();
        assert!(validate_hash(&hash).is_ok());
        assert!(password_valid(b"fixture-password-16", &hash));
        assert!(!password_valid(b"wrong", &hash));
        assert!(validate_hash(&hash.replace("m=32768", "m=4294967295")).is_err());
        assert!(validate_hash(&hash.replace("t=3", "t=9999")).is_err());
        assert!(password_hash(b"short").is_err());
    }
}
