//! HTTPS sessions and scoped tokens. Never called by DNS processing.
use super::{ApiError, ApiJson, ApiPath, AppState, json_body, unavailable};
use crate::{
    auth::{Identity, Role},
    listener::Activity,
};
use axum::{
    Json,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
pub(super) struct LoginBudget {
    global: Window,
    clients: HashMap<IpAddr, Window>,
}
struct Window {
    start: Instant,
    used: u16,
}
impl Default for LoginBudget {
    fn default() -> Self {
        Self {
            global: Window {
                start: Instant::now(),
                used: 0,
            },
            clients: HashMap::new(),
        }
    }
}
impl LoginBudget {
    fn admit(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.clients.retain(|_, window| {
            now.saturating_duration_since(window.start) < Duration::from_secs(60)
        });
        if now.saturating_duration_since(self.global.start) >= Duration::from_secs(60) {
            self.global = Window {
                start: now,
                used: 0,
            };
        }
        if self.global.used >= 30 || (!self.clients.contains_key(&ip) && self.clients.len() >= 256)
        {
            return false;
        }
        let window = self.clients.entry(ip).or_insert(Window {
            start: now,
            used: 0,
        });
        if window.used >= 10 {
            return false;
        }
        window.used += 1;
        self.global.used += 1;
        true
    }
}
#[derive(Clone)]
pub(super) struct Authorization {
    pub role: Role,
    pub csrf: Option<Zeroizing<String>>,
}
pub(super) fn cookie(headers: &HeaderMap) -> Option<String> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        let value = value.to_str().ok()?;
        for part in value.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == "__Host-rustwall" {
                if found.is_some()
                    || value.len() != 64
                    || value
                        .bytes()
                        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
                {
                    return None;
                }
                found = Some(value.to_owned());
            }
        }
    }
    found
}
pub(super) fn csrf_valid(request: &Request, csrf: &str) -> bool {
    let header = request
        .headers()
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());
    if !header.is_some_and(|value| bool::from(value.as_bytes().ct_eq(csrf.as_bytes()))) {
        return false;
    }
    if let Some(origin) = request.headers().get(header::ORIGIN) {
        let Some(origin) = origin
            .to_str()
            .ok()
            .and_then(|value| url::Url::parse(value).ok())
        else {
            return false;
        };
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| request.uri().authority().map(|value| value.as_str()));
        let Some(expected) = host.and_then(|host| url::Url::parse(&format!("https://{host}")).ok())
        else {
            return false;
        };
        if origin.origin() != expected.origin() {
            return false;
        }
    }
    true
}
pub(super) fn role_allowed(role: Role, method: &axum::http::Method, path: &str) -> bool {
    if path == "/api/v1/privacy" && *method == axum::http::Method::PUT {
        return role == Role::Administrator;
    }
    if path.starts_with("/api/v1/auth/")
        && !matches!(path, "/api/v1/auth/session" | "/api/v1/auth/logout")
    {
        return role == Role::Administrator;
    }
    role != Role::ReadOnly || matches!(*method, axum::http::Method::GET | axum::http::Method::HEAD)
}
fn identity(state: &AppState) -> Result<Arc<Identity>, ApiError> {
    state.identity.clone().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "Password administration is not configured".into(),
        )
    })
}
pub(super) async fn info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"password_enabled":state.identity.is_some(),"totp_enabled":state.identity.as_ref().is_some_and(|identity|identity.requires_totp())}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: Zeroizing<String>,
    totp: Option<Zeroizing<String>>,
}
pub(super) async fn login(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let identity = identity(&state)?;
    let activity = request
        .extensions()
        .get::<ConnectInfo<Activity>>()
        .map(|info| info.0.clone())
        .ok_or_else(|| {
            ApiError(
                StatusCode::FORBIDDEN,
                "HTTPS connection context required".into(),
            )
        })?;
    if !activity.secure() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "Password login requires HTTPS".into(),
        ));
    }
    let peer = activity
        .peer()
        .ok_or_else(|| unavailable("Connection identity missing"))?;
    if !state
        .login_budget
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .admit(peer.ip().to_canonical())
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Login attempt budget exceeded".into(),
        ));
    }
    let permit = identity
        .admit_hash()
        .map_err(|error| ApiError(StatusCode::TOO_MANY_REQUESTS, error))?;
    if !request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
        })
    {
        return Err(ApiError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Login requires application/json".into(),
        ));
    }
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        axum::body::to_bytes(request.into_body(), 4096),
    )
    .await
    .map_err(|_| ApiError(StatusCode::REQUEST_TIMEOUT, "Login upload deadline".into()))?
    .map_err(|_| {
        ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Login input exceeds 4 KiB".into(),
        )
    })?;
    let bytes = Zeroizing::new(bytes.to_vec());
    let input: Login = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "Invalid login input".into()))?;
    if input.username.len() > 128 || input.password.len() > 1024 {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "Login input bounds exceeded".into(),
        ));
    }
    let _busy = activity.enter();
    let (result, permit) = tokio::task::spawn_blocking(move || {
        (
            identity.login(
                &input.username,
                input.password.as_bytes(),
                input.totp.as_deref().map(String::as_str),
            ),
            permit,
        )
    })
    .await
    .map_err(unavailable)?;
    let grant = result.map_err(|message| {
        ApiError(
            if message == "Invalid credentials" {
                StatusCode::UNAUTHORIZED
            } else if message == "Session capacity exceeded" {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            message,
        )
    })?;
    #[derive(serde::Serialize)]
    struct Accepted {
        csrf_token: Zeroizing<String>,
        role: Role,
        expires_in_secs: u64,
    }
    let header = format!(
        "__Host-rustwall={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        grant.cookie.as_str(),
        grant.expires_in_secs
    );
    let mut response = json_body(
        StatusCode::OK,
        None,
        Accepted {
            csrf_token: grant.csrf,
            role: Role::Administrator,
            expires_in_secs: grant.expires_in_secs,
        },
        Some(permit),
    )
    .await?;
    response
        .headers_mut()
        .insert(header::SET_COOKIE, header.parse().map_err(unavailable)?);
    Ok(response)
}
pub(super) async fn session(request: Request) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = request
        .extensions()
        .get::<Authorization>()
        .ok_or_else(|| unavailable("Authentication context missing"))?;
    Ok(Json(
        serde_json::json!({"role":auth.role,"csrf_token":auth.csrf.as_ref().map(|value|value.as_str())}),
    ))
}
pub(super) async fn logout(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if let Some(cookie) = cookie(request.headers())
        && let Some(identity) = &state.identity
    {
        identity.logout(&cookie);
    }
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            "__Host-rustwall=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        )],
    )
        .into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenInput {
    name: String,
    role: Role,
    duration_secs: u64,
}
pub(super) async fn tokens(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::auth::TokenMetadata>>, ApiError> {
    Ok(Json(identity(&state)?.tokens()))
}
pub(super) async fn create_token(
    State(state): State<Arc<AppState>>,
    ApiJson(input): ApiJson<TokenInput>,
) -> Result<Response, ApiError> {
    if input.name.is_empty()
        || input.name.len() > 128
        || input.name.chars().any(char::is_control)
        || !(60..=30 * 86400).contains(&input.duration_secs)
    {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Token needs a name and expiry between 60 seconds and 30 days".into(),
        ));
    }
    let permit = state.heavy()?;
    let identity = identity(&state)?;
    let (value, permit) = tokio::task::spawn_blocking(move || {
        (
            identity.create_token(input.name, input.role, input.duration_secs),
            permit,
        )
    })
    .await
    .map_err(unavailable)?;
    #[derive(serde::Serialize)]
    struct Created {
        token: Zeroizing<String>,
    }
    json_body(
        StatusCode::CREATED,
        None,
        Created {
            token: value.map_err(unavailable)?,
        },
        Some(permit),
    )
    .await
}
pub(super) async fn revoke_token(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> Result<Response, ApiError> {
    let permit = state.heavy()?;
    let identity = identity(&state)?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        identity.revoke_token(&id)
    })
    .await
    .map_err(unavailable)?;
    result.map_err(|message| {
        ApiError(
            if message == "Token not found" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            message,
        )
    })?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
pub(super) async fn recover(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let permit = state.heavy()?;
    let identity = identity(&state)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        identity.recover()
    })
    .await
    .map_err(unavailable)?
    .map_err(unavailable)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
