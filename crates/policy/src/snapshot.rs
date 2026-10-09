//! Immutable compiled state. Only assertion-gated compilation constructs it.
use crate::{BindingMetadata, PolicyConfigSet, TemporaryException, exceptions};
use hickory_proto::rr::Record;
use ipnet::IpNet;
use rustwalld_dns_filter::{Decision, FilterSnapshot};
use rustwalld_dns_resolver::Forwarder;
use serde::Serialize;
use std::{collections::HashMap, net::IpAddr, sync::Arc};
pub struct CompiledPolicy {
    pub(crate) id: usize,
    pub(crate) name: String,
    pub(crate) upstream: usize,
    // Shared with other policies of this generation that use identical lists.
    pub(crate) filters: Arc<FilterSnapshot>,
    pub(crate) rewrites: HashMap<String, Vec<Record>>,
    pub(crate) exceptions: Option<exceptions::Entries>,
}
pub(crate) struct ClientBinding {
    pub(crate) policy: usize,
    pub(crate) name: String,
    pub(crate) network: IpNet,
}
#[derive(Serialize)]
pub struct Explanation<'a> {
    pub generation: u64,
    pub client: IpAddr,
    pub client_name: Option<&'a str>,
    pub network: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_metadata: Option<&'a BindingMetadata>,
    pub policy: &'a str,
    pub decision: Decision,
    pub rule: Option<&'a rustwalld_dns_filter::Rule>,
    pub rewrite: bool,
    pub upstream: &'a str,
    pub temporary_exception: Option<&'a TemporaryException>,
}
pub struct Selection<'a> {
    pub policy: &'a CompiledPolicy,
    pub client_name: Option<&'a str>,
    pub network: Option<IpNet>,
}
/// Complete immutable generation, constructible only through validated compilation.
///
/// ```compile_fail
/// use rustwalld_dns_policy::PolicySnapshot;
/// fn bypass(snapshot: &mut PolicySnapshot) { snapshot.generation = 2; }
/// ```
pub struct PolicySnapshot {
    pub(crate) generation: u64,
    pub(crate) config: PolicyConfigSet,
    pub(crate) policies: Vec<CompiledPolicy>,
    pub(crate) upstreams: Vec<Arc<Forwarder>>,
    pub(crate) default: usize,
    pub(crate) ipv4: Vec<(u8, HashMap<u32, ClientBinding>)>,
    pub(crate) ipv6: Vec<(u8, HashMap<u128, ClientBinding>)>,
    // Sparse control-only index into config. Selection never reads annotations.
    pub(crate) metadata: HashMap<IpNet, usize>,
}

// Summaries only: configuration and rule sets can hold hundreds of MiB.
impl std::fmt::Debug for PolicySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicySnapshot")
            .field("generation", &self.generation)
            .field("policies", &self.policies)
            .field("upstreams", &self.upstreams.len())
            .field("default", &self.default)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for CompiledPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPolicy")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("upstream", &self.upstream)
            .field("rules", &self.filters.rules().len())
            .field("rewrites", &self.rewrites.len())
            .finish_non_exhaustive()
    }
}

impl PolicySnapshot {
    /// Identifier included in every cache key and query event.
    #[inline]
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Original validated configuration; cloning it creates a new editable draft.
    #[inline]
    pub fn config(&self) -> &PolicyConfigSet {
        &self.config
    }
    /// Compiled policies in stable configuration order.
    #[inline]
    pub fn policies(&self) -> &[CompiledPolicy] {
        &self.policies
    }
    /// Validated upstream profiles owned by this generation.
    #[inline]
    pub fn upstreams(&self) -> &[Arc<Forwarder>] {
        &self.upstreams
    }
}
impl CompiledPolicy {
    /// Stable index within this generation.
    #[inline]
    pub fn id(&self) -> usize {
        self.id
    }
    /// Human-readable policy identity.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Index of this policy's upstream profile.
    #[inline]
    pub fn upstream(&self) -> usize {
        self.upstream
    }
    /// Immutable rules and provenance.
    #[inline]
    pub fn filters(&self) -> &FilterSnapshot {
        &self.filters
    }
}
