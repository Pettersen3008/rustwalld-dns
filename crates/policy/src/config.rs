//! Serializable policy input; compilation produces immutable snapshots.
use crate::{BindingMetadata, FilterSource, TemporaryException};
use ipnet::IpNet;
use rustwalld_dns_filter::{Action, ListInput};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
/// A named set of upstream addresses sharing one transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProfile {
    /// Unique profile name referenced by policies.
    pub name: String,
    /// Addresses tried in order (1..=8).
    pub addresses: Vec<SocketAddr>,
    /// Per-attempt deadline in milliseconds.
    pub timeout_ms: u64,
    #[serde(
        default,
        skip_serializing_if = "rustwalld_dns_resolver::UpstreamTransport::is_udp"
    )]
    /// UDP (default), DNS-over-TLS or DNS-over-HTTPS.
    pub transport: rustwalld_dns_resolver::UpstreamTransport,
}
/// Filtering, rewrites and exceptions applied to the clients bound to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Unique policy name.
    pub name: String,
    /// Upstream profile name.
    pub upstream: String,
    /// Filter lists; any allow rule wins over every block rule.
    #[serde(default)]
    pub lists: Vec<ListInput>,
    /// Local answers that bypass filtering and forwarding.
    #[serde(default)]
    pub rewrites: Vec<Rewrite>,
    /// Time-limited exact allows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporary_exceptions: Vec<TemporaryException>,
}
/// Local A/AAAA answers for one exact name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    /// Exact name answered locally.
    pub domain: String,
    /// Addresses returned (A for IPv4, AAAA for IPv6).
    pub addresses: Vec<IpAddr>,
    /// Answer TTL in seconds (default 60).
    #[serde(default = "rewrite_ttl")]
    pub ttl: u32,
}
fn rewrite_ttl() -> u32 {
    60
}
/// Selects a policy for clients in a network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// Client network; the longest matching prefix wins.
    pub network: IpNet,
    /// Policy name.
    pub policy: String,
    /// Label shown in diagnostics.
    pub name: String,
    /// Descriptive annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BindingMetadata>,
}
/// A required outcome checked before any generation is published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    /// Client address to evaluate.
    pub client: IpAddr,
    /// Domain to evaluate.
    pub domain: String,
    /// Required decision.
    pub expected: Action,
}
/// Complete policy configuration; compiled into an immutable snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigSet {
    /// Policy for clients without a binding.
    pub default_policy: String,
    /// Policies in stable order.
    pub policies: Vec<PolicyConfig>,
    /// Upstream profiles.
    pub upstreams: Vec<UpstreamProfile>,
    /// Client-to-policy bindings.
    #[serde(default)]
    pub bindings: Vec<Binding>,
    /// Networks allowed to query; others are dropped without a reply.
    pub allowed_clients: Vec<IpNet>,
    /// Required assertions.
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    /// Remote list sources.
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
    Field {
        /// Configuration path, such as `policies[2].name`.
        field: String,
        /// The rule that failed.
        reason: String,
    },
    /// A collection is outside its documented bounds.
    #[error("invalid configuration: {field} has {actual} entries; expected {min} through {max}")]
    Count {
        /// Configuration path of the collection.
        field: String,
        /// Entries supplied.
        actual: usize,
        /// Fewest entries allowed.
        min: usize,
        /// Most entries allowed.
        max: usize,
    },
    /// Generation zero is reserved; hosts allocate identifiers from one.
    #[error("invalid configuration: generation must be nonzero")]
    Generation,
    /// Filter compilation failed.
    #[error(transparent)]
    Filter(#[from] rustwalld_dns_filter::CompileError),
    /// A required assertion failed.
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
