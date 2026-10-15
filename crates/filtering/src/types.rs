//! Control-plane type grammar and immutable rule scope.
use crate::{CompileError, DomainExclusions};
use std::sync::Arc;
/// DNS types that select a rule. Exclusions win; a nonempty inclusion list narrows it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct TypeSelector {
    /// Sorted included wire record types; empty means all types.
    pub include: Box<[u16]>,
    /// Sorted excluded wire record types.
    pub exclude: Box<[u16]>,
}
impl TypeSelector {
    /// Whether this selector applies to a wire record type.
    pub fn matches(&self, kind: u16) -> bool {
        self.exclude.binary_search(&kind).is_err()
            && (self.include.is_empty() || self.include.binary_search(&kind).is_ok())
    }
    pub(super) fn count(&self) -> usize {
        self.include.len() + self.exclude.len()
    }
    pub(super) fn parse(value: &str) -> Result<Self, CompileError> {
        if value.is_empty() || value.split('|').count() > 64 {
            return Err(CompileError::Domain(
                "invalid or oversized dnstype modifier".into(),
            ));
        }
        let (mut include, mut exclude) = (Vec::new(), Vec::new());
        for entry in value.split('|') {
            let (restricted, name) = entry
                .strip_prefix('~')
                .map_or((false, entry), |name| (true, name));
            let name = name.to_ascii_uppercase();
            if matches!(name.as_str(), "*" | "ANAME") {
                return Err(CompileError::Domain("unsupported DNS type".into()));
            }
            let kind = name
                .parse::<hickory_proto::rr::RecordType>()
                .map_err(|_| CompileError::Domain("unsupported DNS type".into()))?;
            if restricted {
                exclude.push(u16::from(kind));
            } else {
                include.push(u16::from(kind));
            }
        }
        include.sort_unstable();
        include.dedup();
        exclude.sort_unstable();
        exclude.dedup();
        Ok(Self {
            include: include.into_boxed_slice(),
            exclude: exclude.into_boxed_slice(),
        })
    }
}
/// Optional scope shared by one immutable rule; flattens into Rule JSON.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct RuleScope {
    /// Domains excluded from this rule only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denyallow: Option<Arc<DomainExclusions>>,
    /// Types included/excluded from this rule only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnstype: Option<TypeSelector>,
    /// Restrictions on actual source-IP/network or explicit binding name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<Box<crate::ClientSelector>>,
    /// Explicit client-tag restrictions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctag: Option<Box<crate::TagSelector>>,
    #[serde(skip)]
    pub(super) ignore_ip_domains: bool,
}
impl RuleScope {
    pub(super) fn applies(
        &self,
        domain: &str,
        kind: u16,
        client: Option<crate::FilterContext<'_>>,
    ) -> bool {
        self.client_matches(client)
            && self
                .dnstype
                .as_ref()
                .is_none_or(|types| types.matches(kind))
            && self.denyallow.as_ref().is_none_or(|domains| {
                !domains.contains(domain)
                    && !(self.ignore_ip_domains && domain.parse::<std::net::IpAddr>().is_ok())
            })
    }
    pub(super) fn client_matches(&self, context: Option<crate::FilterContext<'_>>) -> bool {
        self.client
            .as_ref()
            .is_none_or(|selector| context.is_some_and(|context| selector.matches(context.client)))
            && self.ctag.as_ref().is_none_or(|selector| {
                context.is_some_and(|context| selector.matches(context.tags))
            })
    }
    pub(super) fn payload_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .ctag
                .as_ref()
                .map_or(0, |selector| selector.payload_bytes())
            + self
                .client
                .as_ref()
                .map_or(0, |selector| selector.payload_bytes())
            + self
                .denyallow
                .as_ref()
                .map_or(0, |domains| domains.payload_bytes())
            + self
                .dnstype
                .as_ref()
                .map_or(0, |types| types.count() * std::mem::size_of::<u16>())
    }
}
