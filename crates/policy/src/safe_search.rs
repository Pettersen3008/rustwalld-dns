//! Frozen provider CNAME maps, compiled off the DNS executor.
use crate::{CompiledPolicy, PolicyConfig, PolicyError};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::CNAME};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const GOOGLE: &str = include_str!("safe_search/google-v1.txt");
const BING: &[&str] = &["www.bing.com", "edgeservices.bing.com"];
const DUCKDUCKGO: &[&str] = &[
    "duckduckgo.com",
    "www.duckduckgo.com",
    "start.duckduckgo.com",
];
const YOUTUBE: &[&str] = &[
    "www.youtube.com",
    "m.youtube.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "www.youtube-nocookie.com",
];
fn catalog_version() -> u16 {
    1
}

/// Provider-managed YouTube restricted content mode.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeMode {
    /// No YouTube redirect.
    #[default]
    Off,
    /// Moderate restrictions.
    Moderate,
    /// Strict restrictions.
    Strict,
}
/// Opt-in choices inside one client policy. Version 1 is immutable.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeSearchConfig {
    /// Immutable DNS coverage/target catalog; currently 1.
    #[serde(default = "catalog_version")]
    pub catalog_version: u16,
    /// Google Search www names from the published country-domain catalog.
    #[serde(default)]
    pub google: bool,
    /// Bing Search and the Edge sidebar.
    #[serde(default)]
    pub bing: bool,
    /// DuckDuckGo Search.
    #[serde(default)]
    pub duckduckgo: bool,
    /// YouTube content restrictions.
    #[serde(default)]
    pub youtube: YouTubeMode,
}
impl Default for SafeSearchConfig {
    fn default() -> Self {
        Self {
            catalog_version: 1,
            google: false,
            bing: false,
            duckduckgo: false,
            youtube: YouTubeMode::Off,
        }
    }
}
/// Provider identity retained by a versioned DNS redirect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeSearchProvider {
    /// Google Search.
    Google,
    /// Bing/Edge search.
    Bing,
    /// DuckDuckGo search.
    Duckduckgo,
    /// YouTube content restriction.
    Youtube,
}
/// Selected provider, target and immutable catalog provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SafeSearchMatch {
    /// Selected search/video provider.
    pub provider: SafeSearchProvider,
    /// Provider enforcement DNS name, without a root dot.
    pub target: &'static str,
    /// Catalog version that produced the redirect.
    pub catalog_version: u16,
}
impl SafeSearchConfig {
    /// Whether no provider is selected. Unknown versions still fail validation.
    pub fn is_disabled(&self) -> bool {
        !self.google && !self.bing && !self.duckduckgo && self.youtube == YouTubeMode::Off
    }
    /// Control-plane provenance lookup for a normalized ASCII original name.
    /// This does not resolve addresses or contact any provider.
    pub fn explain(&self, domain: &str) -> Result<Option<SafeSearchMatch>, PolicyError> {
        self.validate("safe_search")?;
        Ok(self
            .providers()
            .into_iter()
            .find_map(|(provider, target, domains)| {
                domains.contains(&domain).then_some(SafeSearchMatch {
                    provider,
                    target,
                    catalog_version: 1,
                })
            }))
    }
    fn validate(&self, field: &str) -> Result<(), PolicyError> {
        if self.catalog_version != 1 {
            return Err(PolicyError::field(
                format!("{field}.catalog_version"),
                "unsupported SafeSearch catalog version",
            ));
        }
        Ok(())
    }
    fn providers(&self) -> Vec<(SafeSearchProvider, &'static str, Vec<&'static str>)> {
        let mut providers = Vec::new();
        if self.google {
            providers.push((
                SafeSearchProvider::Google,
                "forcesafesearch.google.com",
                GOOGLE
                    .lines()
                    .filter(|line| !line.starts_with('#') && !line.is_empty())
                    .collect(),
            ));
        }
        if self.bing {
            providers.push((SafeSearchProvider::Bing, "strict.bing.com", BING.to_vec()));
        }
        if self.duckduckgo {
            providers.push((
                SafeSearchProvider::Duckduckgo,
                "safe.duckduckgo.com",
                DUCKDUCKGO.to_vec(),
            ));
        }
        if self.youtube != YouTubeMode::Off {
            providers.push((
                SafeSearchProvider::Youtube,
                if self.youtube == YouTubeMode::Strict {
                    "restrict.youtube.com"
                } else {
                    "restrictmoderate.youtube.com"
                },
                YOUTUBE.to_vec(),
            ));
        }
        providers
    }
}
pub(crate) struct Mapping {
    target: Name,
    records: [Record; 1],
    provenance: SafeSearchMatch,
}
pub(crate) struct Entries {
    mappings: HashMap<String, Mapping>,
}
impl Entries {
    pub(crate) fn compile(input: &SafeSearchConfig, field: &str) -> Result<Self, PolicyError> {
        input.validate(field)?;
        let mut mappings = HashMap::new();
        for (provider, target, domains) in input.providers() {
            let name = Name::from_ascii(format!("{target}."))
                .map_err(|_| PolicyError::field(field, "invalid built-in SafeSearch target"))?;
            for domain in domains {
                let normalized = rustwalld_dns_filter::normalize(domain)
                    .map_err(|_| PolicyError::field(field, "invalid built-in SafeSearch owner"))?;
                if normalized != domain {
                    return Err(PolicyError::field(
                        field,
                        "built-in SafeSearch owners must be canonical ASCII without a root dot",
                    ));
                }
                if mappings.len() >= 256 {
                    return Err(PolicyError::field(
                        field,
                        "SafeSearch catalog exceeds 256 exact owners",
                    ));
                }
                let owner = Name::from_ascii(format!("{domain}."))
                    .map_err(|_| PolicyError::field(field, "invalid built-in SafeSearch owner"))?;
                let mapping = Mapping {
                    target: name.clone(),
                    records: [Record::from_rdata(
                        owner,
                        60,
                        RData::CNAME(CNAME(name.clone())),
                    )],
                    provenance: SafeSearchMatch {
                        provider,
                        target,
                        catalog_version: 1,
                    },
                };
                if mappings.insert(domain.to_owned(), mapping).is_some() {
                    return Err(PolicyError::field(
                        field,
                        "duplicate built-in SafeSearch owner",
                    ));
                }
            }
        }
        Ok(Self { mappings })
    }
    pub(crate) fn check_conflicts(
        &self,
        input: &PolicyConfig,
        field: &str,
    ) -> Result<(), PolicyError> {
        for domain in input
            .rewrites
            .iter()
            .map(|record| record.domain.as_str())
            .chain(
                input
                    .dns_records
                    .iter()
                    .map(|record| record.domain.as_str()),
            )
        {
            let (domain, name) = crate::local_dns::normalized_owner(domain, field.to_owned())?;
            let covered = |value: &str| {
                if name.is_wildcard() {
                    domain.strip_prefix("*.").is_some_and(|suffix| {
                        crate::rewrite::suffixes(value).any(|part| part == suffix)
                    })
                } else {
                    value == domain
                }
            };
            if self.mappings.keys().any(|owner| covered(owner))
                || self
                    .mappings
                    .values()
                    .any(|mapping| covered(mapping.provenance.target))
            {
                return Err(PolicyError::field(
                    field,
                    "SafeSearch owner/target conflicts with an explicit local DNS record; remove the record or disable that provider",
                ));
            }
        }
        Ok(())
    }
}
impl CompiledPolicy {
    /// Precompiled redirect answer for a normalized original query name. Filters
    /// must permit the name before using this result. CNAME queries stay local.
    pub fn safe_search_answer(
        &self,
        domain: &str,
        kind: RecordType,
    ) -> Option<(&[Record], Option<&Name>)> {
        let mapping = self.safe_search.as_ref()?.mappings.get(domain)?;
        Some((
            &mapping.records,
            (kind != RecordType::CNAME).then_some(&mapping.target),
        ))
    }
    /// Provider/target/catalog selected for this exact original name, if enabled.
    pub fn safe_search_match(&self, domain: &str) -> Option<SafeSearchMatch> {
        Some(self.safe_search.as_ref()?.mappings.get(domain)?.provenance)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Assertion, PolicyConfigSet, PolicySnapshot, Rewrite};
    use rustwalld_dns_filter::{Action, ListInput};
    #[test]
    fn defaults_old_configs_and_exact_catalog_coverage_are_stable() {
        let mut config = PolicyConfigSet::default();
        assert!(
            !serde_json::to_string(&config)
                .unwrap()
                .contains("safe_search")
        );
        let before = PolicySnapshot::compile(config.clone(), 1).unwrap();
        assert!(
            before.policies()[0]
                .safe_search_answer("www.google.com", RecordType::A)
                .is_none()
        );
        let all = SafeSearchConfig {
            google: true,
            bing: true,
            duckduckgo: true,
            youtube: YouTubeMode::Strict,
            ..Default::default()
        };
        config.policies[0].safe_search = Some(all.clone());
        let snapshot = PolicySnapshot::compile(config, 2).unwrap();
        let policy = &snapshot.policies()[0];
        assert_eq!(policy.safe_search.as_ref().unwrap().mappings.len(), 204);
        for (owner, target) in [
            ("www.google.no", "forcesafesearch.google.com"),
            ("www.google.com.ai", "forcesafesearch.google.com"),
            ("edgeservices.bing.com", "strict.bing.com"),
            ("start.duckduckgo.com", "safe.duckduckgo.com"),
            ("youtubei.googleapis.com", "restrict.youtube.com"),
        ] {
            let mapping = policy.safe_search_match(owner).unwrap();
            assert_eq!(mapping.target, target);
            assert_eq!(mapping.catalog_version, 1);
            assert_eq!(all.explain(owner).unwrap(), Some(mapping));
            assert!(
                policy
                    .safe_search_answer(owner, RecordType::A)
                    .unwrap()
                    .1
                    .is_some()
            );
            assert!(
                policy
                    .safe_search_answer(owner, RecordType::CNAME)
                    .unwrap()
                    .1
                    .is_none()
            );
        }
        for owner in [
            "youtube.com",
            "youtu.be",
            "s.ytimg.com",
            "googleapis.com",
            "google.com",
            "child.www.google.com",
            "www.google.com.attacker.test",
        ] {
            assert!(policy.safe_search_match(owner).is_none(), "{owner}");
        }
        let mut moderate = all;
        moderate.youtube = YouTubeMode::Moderate;
        assert_eq!(
            moderate.explain("www.youtube.com").unwrap().unwrap().target,
            "restrictmoderate.youtube.com"
        );
    }
    #[test]
    fn identical_client_settings_share_one_map_and_block_assertions_still_win() {
        let mut config = PolicyConfigSet::default();
        config.policies[0].safe_search = Some(SafeSearchConfig {
            google: true,
            ..Default::default()
        });
        config.policies[0].lists = vec![ListInput {
            name: "block-search".into(),
            action: Action::Block,
            rules: "www.google.com".into(),
            syntax: Default::default(),
        }];
        config.assertions = vec![Assertion {
            qtype: 1,
            client: "127.0.0.1".parse().unwrap(),
            domain: "www.google.com".into(),
            expected: Action::Block,
        }];
        let mut second = config.policies[0].clone();
        second.name = "second".into();
        config.policies.push(second);
        let snapshot = PolicySnapshot::compile(config, 1).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            snapshot.policies()[0].safe_search.as_ref().unwrap(),
            snapshot.policies()[1].safe_search.as_ref().unwrap()
        ));
        let trace = snapshot
            .explain("127.0.0.1".parse().unwrap(), "www.google.com")
            .unwrap();
        assert_eq!(trace.decision.action, Action::Block);
        assert!(!trace.rewrite);
        assert!(trace.safe_search.is_none());
    }
    #[test]
    fn unknown_versions_and_conflicting_local_owners_or_targets_fail_closed() {
        let mut config = PolicyConfigSet::default();
        config.policies[0].safe_search = Some(SafeSearchConfig {
            catalog_version: 2,
            ..Default::default()
        });
        assert!(PolicySnapshot::compile(config.clone(), 1).is_err());
        config.policies[0].safe_search = Some(SafeSearchConfig {
            google: true,
            ..Default::default()
        });
        for domain in ["WWW.Google.Com.", "forcesafesearch.google.com"] {
            config.policies[0].rewrites = vec![Rewrite {
                domain: domain.into(),
                addresses: vec!["192.0.2.1".parse().unwrap()],
                ttl: 60,
            }];
            assert!(PolicySnapshot::compile(config.clone(), 1).is_err());
        }
        config.policies[0].rewrites.clear();
        assert!(PolicySnapshot::compile(config, 1).is_ok());
    }
}
