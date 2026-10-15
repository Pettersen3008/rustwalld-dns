//! Immutable compiled state. Only assertion-gated compilation constructs it.
use crate::{BindingMetadata, PolicyConfigSet, TemporaryException, exceptions};
use ipnet::IpNet;
use rustwalld_dns_filter::{Decision, FilterSnapshot};
use rustwalld_dns_resolver::Forwarder;
use serde::Serialize;
use std::{collections::HashMap, net::IpAddr, sync::Arc};
/// One compiled policy within a snapshot.
pub struct CompiledPolicy {
    pub(crate) id: usize,
    pub(crate) name: String,
    pub(crate) upstream: usize,
    pub(crate) ds_routing: crate::DsRouting,
    // Shared with other policies of this generation that use identical lists.
    pub(crate) filters: Arc<FilterSnapshot>,
    pub(crate) services_off: Option<Arc<FilterSnapshot>>,
    pub(crate) schedule: Option<Arc<crate::schedules::CompiledSchedule>>,
    pub(crate) rewrites: crate::rewrite::Rewrites,
    pub(crate) exceptions: Option<exceptions::Entries>,
    pub(crate) routes: Vec<(hickory_proto::rr::Name, usize)>,
    pub(crate) block_mode: crate::BlockMode,
    pub(crate) safe_search: Option<Arc<crate::safe_search::Entries>>,
}
pub(crate) struct ClientBinding {
    pub(crate) policy: usize,
    pub(crate) name: String,
    pub(crate) network: IpNet,
    pub(crate) filter_tags: rustwalld_dns_filter::ClientTags,
}
/// Answer to [`PolicySnapshot::explain`].
#[derive(Serialize)]
pub struct Explanation<'a> {
    /// Generation explained.
    pub generation: u64,
    /// Client address explained.
    pub client: IpAddr,
    /// Whether `allowed_clients` admits this client. DNS silently drops queries
    /// from clients that are not admitted; the remaining trace is hypothetical.
    pub permitted: bool,
    /// Name of the matching binding, if any.
    pub client_name: Option<&'a str>,
    /// Network of the matching binding, if any.
    pub network: Option<IpNet>,
    /// Annotations of the matching binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_metadata: Option<&'a BindingMetadata>,
    /// Explicit filtering tags assigned by the selected binding.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filter_tags: Vec<&'static str>,
    /// Selected policy name.
    pub policy: &'a str,
    /// Filter decision (allow when a rewrite or temporary exception applies).
    pub decision: Decision,
    /// Deciding rule with provenance.
    pub rule: Option<&'a rustwalld_dns_filter::Rule>,
    /// Whether a local rewrite answers the name.
    pub rewrite: bool,
    /// Provider redirect applied after an allowed filter decision, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_search: Option<crate::SafeSearchMatch>,
    /// Actual civil-time schedule, absent for permanent assertion traces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_schedule: Option<crate::ScheduleExplanation<'a>>,
    /// Upstream profile the policy forwards to.
    pub upstream: &'a str,
    /// Temporary exception in force, if any.
    pub temporary_exception: Option<&'a TemporaryException>,
}
/// Policy selected for a client.
pub struct Selection<'a> {
    /// The selected policy.
    pub policy: &'a CompiledPolicy,
    /// Name of the matching binding, if any.
    pub client_name: Option<&'a str>,
    /// Network of the matching binding, if any.
    pub network: Option<IpNet>,
    /// Explicit precompiled tags from this binding.
    pub filter_tags: rustwalld_dns_filter::ClientTags,
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
    /// Most-specific route for the actual lookup name, or this policy's default.
    pub fn upstream_for(&self, name: &hickory_proto::rr::Name) -> usize {
        self.routes
            .iter()
            .find(|(zone, _)| zone.zone_of(name))
            .map_or(self.upstream, |(_, index)| *index)
    }
    /// Select the resolver for the actual lookup question. Parent DS mode excludes
    /// an exact-name route while retaining its strictly ancestral suffixes.
    pub fn upstream_for_query(
        &self,
        name: &hickory_proto::rr::Name,
        kind: hickory_proto::rr::RecordType,
    ) -> usize {
        if kind != hickory_proto::rr::RecordType::DS || self.ds_routing != crate::DsRouting::Parent
        {
            return self.upstream_for(name);
        }
        self.routes
            .iter()
            .find(|(zone, _)| zone.len() < name.len() && zone.zone_of(name))
            .map_or(self.upstream, |(_, index)| *index)
    }
    /// Synthesis mode for policy blocks.
    pub fn block_mode(&self) -> crate::BlockMode {
        self.block_mode
    }
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
