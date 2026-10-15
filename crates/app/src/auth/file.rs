//! Durable private identity state. Loaded/changed only on control workers.
use super::crypto;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    ReadOnly,
    Operator,
    Administrator,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct User {
    pub name: String,
    pub password_hash: String,
    pub totp_secret: Option<Zeroizing<String>>,
    pub last_totp_step: Option<u64>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Token {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub expires_at: u64,
    pub digest: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdentityFile {
    pub schema: u32,
    pub revision: u64,
    pub user: User,
    pub tokens: Vec<Token>,
}
pub(super) fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| !character.is_control())
}
impl IdentityFile {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || self.revision == 0
            || !label(&self.user.name)
            || self.tokens.len() > 64
        {
            return Err("Invalid credential schema, revision, username or token count".into());
        }
        crypto::validate_hash(&self.user.password_hash)?;
        if let Some(secret) = &self.user.totp_secret {
            crypto::decode_secret(secret)?;
        } else if self.user.last_totp_step.is_some() {
            return Err("Replay counter requires TOTP".into());
        }
        let mut ids = HashSet::new();
        for token in &self.tokens {
            if !label(&token.name)
                || token.id.len() != 32
                || token
                    .id
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
                || !ids.insert(&token.id)
                || token.expires_at == 0
                || token.expires_at > 253402300799
                || token.digest.len() != 64
                || token
                    .digest
                    .bytes()
                    .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
            {
                return Err("Invalid or duplicate scoped token".into());
            }
        }
        Ok(())
    }
}
pub(super) fn load(path: &Path) -> Result<IdentityFile, String> {
    let file = std::fs::File::open(path).map_err(|_| "Cannot open private credential file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file
            .metadata()
            .map_err(|_| "Cannot inspect credential permissions")?
            .permissions()
            .mode()
            & 0o007
            != 0
        {
            return Err("Credential file must not be accessible to other users".into());
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read credential file")?;
    decode(&bytes)
}
pub(super) fn decode(bytes: &[u8]) -> Result<IdentityFile, String> {
    if bytes.len() > 65536 {
        return Err("Credential file exceeds 64 KiB".into());
    }
    let value: IdentityFile =
        serde_json::from_slice(bytes).map_err(|_| "Invalid credential JSON")?;
    value.validate()?;
    Ok(value)
}
pub(super) fn save(path: &Path, value: &IdentityFile, create: bool) -> Result<(), String> {
    value.validate()?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let bytes =
        Zeroizing::new(serde_json::to_vec(value).map_err(|_| "Cannot encode credential file")?);
    if bytes.len() > 65536 {
        return Err("Credential file exceeds 64 KiB".into());
    }
    let mut staged =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "Cannot stage private credentials")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "Cannot secure staged credentials")?;
    }
    staged
        .write_all(&bytes)
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|_| "Cannot sync staged credentials")?;
    if create {
        staged
            .persist_noclobber(path)
            .map_err(|_| "Credential file already exists or cannot be created")?;
    } else {
        staged
            .persist(path)
            .map_err(|_| "Cannot atomically replace credentials")?;
    }
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "Cannot sync credential directory")?;
    Ok(())
}
/// Initialize an absent credential file; password bytes must come from stdin.
/// Returns a provisioning URI only when TOTP is requested. Do not log it.
pub fn initialize(
    path: PathBuf,
    username: String,
    password: &[u8],
    totp: bool,
) -> Result<Option<Zeroizing<String>>, String> {
    if !label(&username) {
        return Err("Username requires 1..128 non-control bytes".into());
    }
    let secret = if totp {
        Some(crypto::totp_secret()?)
    } else {
        None
    };
    let provision=secret.as_ref().map(|secret| {
        let encoded:String=url::form_urlencoded::byte_serialize(username.as_bytes()).collect();
        Zeroizing::new(format!("otpauth://totp/Rustwall:{encoded}?secret={}&issuer=Rustwall&algorithm=SHA1&digits=6&period=30",secret.as_str()))
    });
    let file = IdentityFile {
        schema: 1,
        revision: 1,
        user: User {
            name: username,
            password_hash: crypto::password_hash(password)?,
            totp_secret: secret,
            last_totp_step: None,
        },
        tokens: vec![],
    };
    save(&path, &file, true)?;
    Ok(provision)
}
/// Read a private container/systemd master-token credential at startup only.
pub fn master_token(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| "Master-token file unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Master-token metadata unavailable")?;
    if !metadata.is_file() {
        return Err("Master-token must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Master-token file requires private 0600 permissions".into());
        }
    }
    let mut token = zeroize::Zeroizing::new(String::new());
    file.take(1027)
        .read_to_string(&mut token)
        .map_err(|_| "Master-token unreadable")?;
    if token.ends_with('\n') {
        token.pop();
        if token.ends_with('\r') {
            token.pop();
        }
    }
    if !(16..=1024).contains(&token.len()) || token.bytes().any(|b| b.is_ascii_control()) {
        return Err("Master-token must contain 16..1024 bytes without control characters".into());
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[cfg(unix)]
    #[test]
    fn master_file_enforces_private_permissions_bounds_and_line_endings() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        std::fs::write(&path, "fixture-master-token-at-least16\r\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            master_token(&path).unwrap().as_str(),
            "fixture-master-token-at-least16"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(master_token(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        for value in [
            "short".to_owned(),
            "a".repeat(1025),
            "fixture-master-token\nsecond-line".to_owned(),
        ] {
            std::fs::write(&path, value).unwrap();
            assert!(master_token(&path).is_err());
        }
        assert!(master_token(directory.path()).is_err());
    }
    #[test]
    fn private_file_initialization_never_overwrites_and_rejects_cost_or_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        let uri = initialize(path.clone(), "admin".into(), b"fixture-password-16", true)
            .unwrap()
            .unwrap();
        assert!(uri.starts_with("otpauth://totp/Rustwall:admin?secret="));
        let mut file = load(&path).unwrap();
        assert!(file.user.totp_secret.is_some());
        assert!(initialize(path.clone(), "admin".into(), b"fixture-password-16", false).is_err());
        file.user.password_hash = file.user.password_hash.replace("m=32768", "m=99999999");
        assert!(save(&path, &file, false).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load(&path).is_err());
        }
    }
}
