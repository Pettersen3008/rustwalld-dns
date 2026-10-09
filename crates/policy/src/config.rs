//! Serializable policy input; compilation produces immutable snapshots.
use crate::{BindingMetadata, FilterSource, TemporaryException};
use ipnet::IpNet;
use rustwalld_dns_filter::{Action, ListInput};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProfile {
    pub name: String,
    pub addresses: Vec<SocketAddr>,
    pub timeout_ms: u64,
    #[serde(
        default,
        skip_serializing_if = "rustwalld_dns_resolver::UpstreamTransport::is_udp"
    )]
    pub transport: rustwalld_dns_resolver::UpstreamTransport,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub name: String,
    pub upstream: String,
    #[serde(default)]
    pub lists: Vec<ListInput>,
    #[serde(default)]
    pub rewrites: Vec<Rewrite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporary_exceptions: Vec<TemporaryException>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    pub domain: String,
    pub addresses: Vec<IpAddr>,
    #[serde(default = "rewrite_ttl")]
    pub ttl: u32,
}
fn rewrite_ttl() -> u32 {
    60
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub network: IpNet,
    pub policy: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BindingMetadata>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub client: IpAddr,
    pub domain: String,
    pub expected: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigSet {
    pub default_policy: String,
    pub policies: Vec<PolicyConfig>,
    pub upstreams: Vec<UpstreamProfile>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    pub allowed_clients: Vec<IpNet>,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter_sources: Vec<FilterSource>,
}
impl Default for PolicyConfigSet {
    fn default() -> Self {
        Self {
            default_policy: "default".into(),
            policies: vec![PolicyConfig {
                name: "default".into(),
                upstream: "default".into(),
                lists: vec![],
                rewrites: vec![],
                temporary_exceptions: vec![],
            }],
            upstreams: vec![UpstreamProfile {
                name: "default".into(),
                addresses: vec![
                    SocketAddr::from(([1, 1, 1, 1], 53)),
                    SocketAddr::from(([9, 9, 9, 9], 53)),
                ],
                timeout_ms: 1500,
                transport: rustwalld_dns_resolver::UpstreamTransport::Udp,
            }],
            bindings: vec![],
            allowed_clients: vec![
                IpNet::from(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                IpNet::from(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            ],
            assertions: vec![],
            filter_sources: vec![],
        }
    }
}
/// Compilation or validation failure. Messages name the failing field and a
/// bounded, escaped excerpt of the offending value; they never echo list text.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// Validation failure without a more specific variant.
    #[error("invalid configuration: {0}")]
    Invalid(String),
    /// A field failed validation. `field` is a configuration path such as
    /// `policies[2].name`; `reason` explains the rule that failed.
    #[error("invalid configuration: {field}: {reason}")]
    Field { field: String, reason: String },
    /// A collection is outside its documented bounds.
    #[error("invalid configuration: {field} has {actual} entries; expected {min} through {max}")]
    Count {
        field: String,
        actual: usize,
        min: usize,
        max: usize,
    },
    /// Generation zero is reserved; hosts allocate identifiers from one.
    #[error("invalid configuration: generation must be nonzero")]
    Generation,
    #[error(transparent)]
    Filter(#[from] rustwalld_dns_filter::CompileError),
    #[error("required policy assertion failed: {0}")]
    Assertion(String),
}
impl PolicyError {
    pub(crate) fn field(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Field {
            field: field.into(),
            reason: reason.into(),
        }
    }
    /// Reject `actual` outside `min..=max` for the named collection.
    pub(crate) fn check_count(
        field: impl FnOnce() -> String,
        actual: usize,
        min: usize,
        max: usize,
    ) -> Result<(), Self> {
        if (min..=max).contains(&actual) {
            Ok(())
        } else {
            Err(Self::Count {
                field: field(),
                actual,
                min,
                max,
            })
        }
    }
}
/// Names are labels shown in diagnostics and the console. Reject blank,
/// oversized and control/bidirectional-formatting text that can disguise a name.
pub(crate) fn validate_name(name: &str, field: impl FnOnce() -> String) -> Result<(), PolicyError> {
    let reason = if name.trim().is_empty() {
        "must not be empty or whitespace-only"
    } else if name.len() > 128 {
        "must be at most 128 bytes"
    } else if name
        .chars()
        .any(|c| c.is_control() || is_bidi_formatting(c))
    {
        "must not contain control or bidirectional formatting characters"
    } else {
        return Ok(());
    };
    Err(PolicyError::field(
        field(),
        format!("{} {reason}", excerpt(name)),
    ))
}
fn is_bidi_formatting(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}
/// Bounded, escaped excerpt of user input for diagnostics.
pub(crate) fn excerpt(value: &str) -> String {
    const MAX_CHARS: usize = 64;
    let mut shown: String = value.chars().take(MAX_CHARS).collect();
    if shown.len() < value.len() {
        shown.push('…');
    }
    format!("{shown:?}")
}
