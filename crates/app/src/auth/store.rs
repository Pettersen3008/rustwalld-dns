//! Bounded identity/session state. No lock spans an await or network operation.
use super::{
    crypto,
    file::{self, IdentityFile, Role, Token},
};
use arc_swap::ArcSwap;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;
pub struct Identity {
    path: PathBuf,
    live: ArcSwap<IdentityFile>,
    writer: Mutex<()>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    hashing: Arc<Semaphore>,
    failed: AtomicBool,
    token_deadlines: Mutex<HashMap<String, (Instant, bool)>>,
}
struct Session {
    csrf: Zeroizing<String>,
    deadline: Instant,
    last_seen: Instant,
}
pub struct SessionGrant {
    pub cookie: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
    pub expires_in_secs: u64,
}
pub struct SessionIdentity {
    pub role: Role,
    pub csrf: Zeroizing<String>,
}
impl Identity {
    /// Load on a startup blocking worker, before serving authentication.
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let state = file::load(&path)?;
        let token_deadlines = deadlines(&state)?;
        Ok(Self {
            path,
            live: ArcSwap::from_pointee(state),
            writer: Mutex::new(()),
            sessions: Mutex::new(HashMap::new()),
            hashing: Arc::new(Semaphore::new(2)),
            failed: AtomicBool::new(false),
            token_deadlines: Mutex::new(token_deadlines),
        })
    }
    pub fn requires_totp(&self) -> bool {
        self.live.load().user.totp_secret.is_some()
    }
    /// Admission follows any surviving password job after caller cancellation.
    pub fn admit_hash(&self) -> Result<OwnedSemaphorePermit, String> {
        self.hashing
            .clone()
            .try_acquire_owned()
            .map_err(|_| "Login verification capacity exceeded".into())
    }
    /// Blocking verification. Any TOTP replay step is durable before minting.
    pub fn login(
        &self,
        username: &str,
        password: &[u8],
        totp: Option<&str>,
    ) -> Result<SessionGrant, String> {
        if self.failed.load(Ordering::Acquire) {
            return Err("Identity persistence needs administrator recovery".into());
        }
        let pinned = self.live.load_full();
        let password_valid = crypto::password_valid(password, &pinned.user.password_hash);
        if !password_valid || !bool::from(username.as_bytes().ct_eq(pinned.user.name.as_bytes())) {
            return Err("Invalid credentials".into());
        }
        let step = if let Some(secret) = &pinned.user.totp_secret {
            let secret = crypto::decode_secret(secret)?;
            Some(
                crypto::totp_step(
                    &secret,
                    totp.unwrap_or(""),
                    seconds()?,
                    pinned.user.last_totp_step,
                )
                .ok_or("Invalid credentials")?,
            )
        } else {
            if totp.is_some_and(|value| !value.is_empty()) {
                return Err("Invalid credentials".into());
            }
            None
        };
        // Serialize replay updates, but never while hashing or checking HTTP.
        if let Some(step) = step {
            self.mutate(|state| {
                if state.revision != pinned.revision
                    || state.user.last_totp_step.is_some_and(|last| step <= last)
                {
                    return Err("Invalid credentials".into());
                }
                state.user.last_totp_step = Some(step);
                Ok(())
            })?;
        } else if self.live.load().revision != pinned.revision {
            return Err("Credentials changed during login".into());
        }
        let cookie = Zeroizing::new(crypto::nonce()?);
        let csrf = Zeroizing::new(crypto::nonce()?);
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let expected = pinned
            .revision
            .checked_add(u64::from(step.is_some()))
            .ok_or("Identity revision exhausted")?;
        if self.live.load().revision != expected || self.failed.load(Ordering::Acquire) {
            return Err("Credentials changed during login".into());
        }
        sessions.retain(|_, session| {
            session.deadline > now
                && now.saturating_duration_since(session.last_seen) < Duration::from_secs(1800)
        });
        if sessions.len() >= 64 {
            return Err("Session capacity exceeded".into());
        }
        sessions.insert(
            crypto::hash_token(cookie.as_bytes()),
            Session {
                csrf: csrf.clone(),
                deadline: now + Duration::from_secs(8 * 3600),
                last_seen: now,
            },
        );
        Ok(SessionGrant {
            cookie,
            csrf,
            expires_in_secs: 8 * 3600,
        })
    }
    pub fn session(&self, cookie: &str) -> Option<SessionIdentity> {
        if self.failed.load(Ordering::Acquire) || cookie.len() != 64 {
            return None;
        }
        let hash = crypto::hash_token(cookie.as_bytes());
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let session = sessions.get_mut(&hash)?;
        if session.deadline <= now
            || now.saturating_duration_since(session.last_seen) >= Duration::from_secs(1800)
        {
            sessions.remove(&hash);
            return None;
        }
        session.last_seen = now;
        Some(SessionIdentity {
            role: Role::Administrator,
            csrf: session.csrf.clone(),
        })
    }
    pub fn logout(&self, cookie: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&crypto::hash_token(cookie.as_bytes()));
    }
    pub fn token_role(&self, token: &str) -> Option<Role> {
        if self.failed.load(Ordering::Acquire) || token.len() > 1024 {
            return None;
        }
        let now = seconds().ok()?;
        let hash = data_encoding::HEXLOWER.encode(&crypto::hash_token(token.as_bytes()));
        let live = self.live.load();
        let token = live
            .tokens
            .iter()
            .find(|token| bool::from(hash.as_bytes().ct_eq(token.digest.as_bytes())))?;
        let mut deadlines = self
            .token_deadlines
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (deadline, expired) = deadlines.get_mut(&token.id)?;
        if *expired || token.expires_at <= now || Instant::now() >= *deadline {
            *expired = true;
            return None;
        }
        Some(token.role)
    }
    /// Durably mint a scoped automation token. Return its value only once.
    pub fn create_token(
        &self,
        name: String,
        role: Role,
        duration_secs: u64,
    ) -> Result<Zeroizing<String>, String> {
        if !file::label(&name) || !(60..=30 * 86400).contains(&duration_secs) {
            return Err("Token needs a name and an expiry between 60 seconds and 30 days".into());
        }
        let secret = Zeroizing::new(crypto::nonce()?);
        let id = crypto::nonce()?[..32].to_owned();
        let expires_at = seconds()?
            .checked_add(duration_secs)
            .ok_or("Token expiry overflow")?;
        self.mutate(|state| {
            if state.tokens.len() >= 64 {
                return Err("Token capacity exceeded".into());
            }
            state.tokens.push(Token {
                id,
                name,
                role,
                expires_at,
                digest: data_encoding::HEXLOWER.encode(&crypto::hash_token(secret.as_bytes())),
            });
            Ok(())
        })?;
        Ok(secret)
    }
    pub fn tokens(&self) -> Vec<TokenMetadata> {
        self.live
            .load()
            .tokens
            .iter()
            .map(|token| TokenMetadata {
                id: token.id.clone(),
                name: token.name.clone(),
                role: token.role,
                expires_at: token.expires_at,
            })
            .collect()
    }
    pub fn revoke_token(&self, id: &str) -> Result<(), String> {
        self.mutate(|state| {
            let len = state.tokens.len();
            state.tokens.retain(|token| token.id != id);
            if state.tokens.len() == len {
                return Err("Token not found".into());
            }
            Ok(())
        })
    }
    /// Reload after a failed/uncertain file write using emergency administration.
    pub fn recover(&self) -> Result<(), String> {
        let _writer = self
            .writer
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut state = file::load(&self.path)?;
        let previous = self.live.load_full();
        if state.user.name == previous.user.name
            && state.user.totp_secret == previous.user.totp_secret
        {
            state.user.last_totp_step = state.user.last_totp_step.max(previous.user.last_totp_step);
        }
        state.revision = state
            .revision
            .max(previous.revision)
            .checked_add(1)
            .ok_or("Identity revision exhausted")?;
        let next_deadlines = deadlines(&state)?;
        file::save(&self.path, &state, false)?;
        self.update_deadlines(next_deadlines);
        self.live.store(Arc::new(state));
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.failed.store(false, Ordering::Release);
        Ok(())
    }
    fn mutate(
        &self,
        change: impl FnOnce(&mut IdentityFile) -> Result<(), String>,
    ) -> Result<(), String> {
        let _writer = self
            .writer
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.failed.load(Ordering::Acquire) {
            return Err("Identity persistence needs administrator recovery".into());
        }
        let mut state = (*self.live.load_full()).clone();
        change(&mut state)?;
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or("Identity revision exhausted")?;
        let next_deadlines = deadlines(&state)?;
        if let Err(error) = file::save(&self.path, &state, false) {
            self.failed.store(true, Ordering::Release);
            return Err(error);
        }
        self.update_deadlines(next_deadlines);
        self.live.store(Arc::new(state));
        Ok(())
    }
    fn update_deadlines(&self, mut next: HashMap<String, (Instant, bool)>) {
        let mut current = self
            .token_deadlines
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for (id, value) in &mut next {
            if let Some(previous) = current.get(id) {
                value.0 = value.0.min(previous.0);
                value.1 |= previous.1;
            }
        }
        *current = next;
    }
}
fn deadlines(state: &IdentityFile) -> Result<HashMap<String, (Instant, bool)>, String> {
    let wall = seconds()?;
    let now = Instant::now();
    Ok(state
        .tokens
        .iter()
        .map(|token| {
            (
                token.id.clone(),
                (
                    now + Duration::from_secs(
                        token.expires_at.saturating_sub(wall).min(30 * 86400),
                    ),
                    token.expires_at <= wall,
                ),
            )
        })
        .collect())
}
#[derive(serde::Serialize)]
pub struct TokenMetadata {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub expires_at: u64,
}
fn seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "System clock is before Unix epoch".into())
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn replay_is_durable_and_concurrent_logins_cannot_reuse_a_totp_step() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        file::initialize(path.clone(), "admin".into(), b"fixture-password-16", true).unwrap();
        let stored = file::load(&path).unwrap();
        let secret = crypto::decode_secret(stored.user.totp_secret.as_ref().unwrap()).unwrap();
        let code = crypto::code(&secret, seconds().unwrap() / 30, 6);
        let identity = Arc::new(Identity::load(path.clone()).unwrap());
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                let identity = identity.clone();
                let code = code.clone();
                std::thread::spawn(move || {
                    identity
                        .login("admin", b"fixture-password-16", Some(&code))
                        .is_ok()
                })
            })
            .collect();
        let successes = tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
        assert!(
            Identity::load(path)
                .unwrap()
                .login("admin", b"fixture-password-16", Some(&code))
                .is_err()
        );
    }
    #[test]
    fn recovery_advances_revision_and_preserves_replay_for_the_same_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        file::initialize(path.clone(), "admin".into(), b"fixture-password-16", true).unwrap();
        let old = file::load(&path).unwrap();
        let identity = Identity::load(path.clone()).unwrap();
        let secret = crypto::decode_secret(old.user.totp_secret.as_ref().unwrap()).unwrap();
        let code = crypto::code(&secret, seconds().unwrap() / 30, 6);
        identity
            .login("admin", b"fixture-password-16", Some(&code))
            .unwrap();
        let revision = identity.live.load().revision;
        file::save(&path, &old, false).unwrap();
        identity.recover().unwrap();
        assert!(identity.live.load().revision > revision);
        assert!(
            identity
                .login("admin", b"fixture-password-16", Some(&code))
                .is_err()
        );
    }
    #[test]
    fn session_and_token_monotonic_expiry_cannot_revive_on_unrelated_mutations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        file::initialize(path.clone(), "admin".into(), b"fixture-password-16", false).unwrap();
        let identity = Identity::load(path).unwrap();
        let session = identity
            .login("admin", b"fixture-password-16", None)
            .unwrap();
        identity
            .sessions
            .lock()
            .unwrap()
            .get_mut(&crypto::hash_token(session.cookie.as_bytes()))
            .unwrap()
            .deadline = Instant::now();
        assert!(identity.session(&session.cookie).is_none());
        let token = identity
            .create_token("short".into(), Role::Operator, 60)
            .unwrap();
        let id = identity.tokens()[0].id.clone();
        identity
            .token_deadlines
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .0 = Instant::now();
        assert!(identity.token_role(&token).is_none());
        identity
            .create_token("unrelated".into(), Role::ReadOnly, 60)
            .unwrap();
        assert!(identity.token_role(&token).is_none());
    }
    #[test]
    fn sessions_tokens_revoke_restart_and_failure_do_not_publish_undurable_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        file::initialize(path.clone(), "admin".into(), b"fixture-password-16", false).unwrap();
        let identity = Identity::load(path.clone()).unwrap();
        assert!(identity.login("admin", b"wrong", None).is_err());
        let session = identity
            .login("admin", b"fixture-password-16", None)
            .unwrap();
        assert_eq!(
            identity.session(&session.cookie).unwrap().role,
            Role::Administrator
        );
        identity.logout(&session.cookie);
        assert!(identity.session(&session.cookie).is_none());
        let secret = identity
            .create_token("read".into(), Role::ReadOnly, 60)
            .unwrap();
        assert_eq!(identity.token_role(&secret), Some(Role::ReadOnly));
        let metadata = identity.tokens();
        let reloaded = Identity::load(path.clone()).unwrap();
        assert_eq!(reloaded.token_role(&secret), Some(Role::ReadOnly));
        identity.revoke_token(&metadata[0].id).unwrap();
        assert!(
            Identity::load(path.clone())
                .unwrap()
                .token_role(&secret)
                .is_none()
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(directory.path()).unwrap();
        assert!(
            identity
                .create_token("fail".into(), Role::Operator, 60)
                .is_err()
        );
        assert!(
            identity
                .login("admin", b"fixture-password-16", None)
                .is_err()
        );
    }
}
