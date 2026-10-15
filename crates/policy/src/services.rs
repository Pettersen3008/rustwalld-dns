//! Frozen service-domain groups expanded only on the control plane.
use crate::{PolicyConfig, PolicyError};
use rustwalld_dns_filter::{Action, ListInput, RuleSyntax};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet};
const PREFIX: &str = "@service/";
fn version() -> u16 {
    1
}
/// Versioned, opt-in first-party service-domain groups.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedServices {
    /// Immutable catalog identifier; omitted serialized values retain version 1.
    #[serde(default = "version")]
    pub catalog_version: u16,
    /// Unique catalog service IDs. Empty means no service blocking.
    #[serde(default)]
    pub ids: Vec<String>,
    /// Optional civil-time enforcement; absent means always selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<crate::WeeklySchedule>,
}
/// Public coverage of one service in the frozen catalog.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct ServiceDefinition {
    /// Stable ID accepted by [`BlockedServices`].
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Display category; not a category-wide block.
    pub category: &'static str,
    /// Apex and descendants blocked by suffix rules.
    pub suffixes: &'static [&'static str],
    /// Only these names blocked by exact rules.
    pub exact_names: &'static [&'static str],
    /// Optional coverage limits; omitted in the original v1 wire format.
    #[serde(skip_serializing_if = "<[&str]>::is_empty")]
    pub limitations: &'static [&'static str],
    /// Primary provider documentation; never fetched by compilation or queries.
    #[serde(skip_serializing_if = "<[&str]>::is_empty")]
    pub references: &'static [&'static str],
}
/// Frozen catalog v1. No network lookup or content guarantee is implied.
pub fn service_catalog() -> &'static [ServiceDefinition] {
    &CATALOG_V1
}
const CATALOG_V1: [ServiceDefinition; 4] = [
    ServiceDefinition {
        id: "discord",
        name: "Discord",
        category: "Messaging",
        suffixes: &["discord.com", "discord.gg"],
        exact_names: &[],
        limitations: &[],
        references: &[],
    },
    ServiceDefinition {
        id: "reddit",
        name: "Reddit",
        category: "Social",
        suffixes: &["reddit.com"],
        exact_names: &[],
        limitations: &[],
        references: &[],
    },
    ServiceDefinition {
        id: "tiktok",
        name: "TikTok",
        category: "Video",
        suffixes: &["tiktok.com"],
        exact_names: &[],
        limitations: &[],
        references: &[],
    },
    ServiceDefinition {
        id: "youtube",
        name: "YouTube",
        category: "Video",
        suffixes: &["youtube.com", "youtu.be", "youtube-nocookie.com"],
        exact_names: &["youtube.googleapis.com", "youtubei.googleapis.com"],
        limitations: &[],
        references: &[],
    },
];
/// Newest supported catalog; choosing it never changes existing revisions.
pub const LATEST_SERVICE_CATALOG_VERSION: u16 = 2;
/// Immutable coverage for an explicit version, rejecting unknown catalogs.
pub fn service_catalog_for_version(
    version: u16,
) -> Result<&'static [ServiceDefinition], PolicyError> {
    match version {
        1 => Ok(&CATALOG_V1),
        2 => Ok(&CATALOG_V2),
        _ => Err(PolicyError::field(
            "blocked_services.catalog_version",
            "unsupported service catalog version",
        )),
    }
}
const CATALOG_V2: [ServiceDefinition; 12] = [
    CATALOG_V1[0],
    CATALOG_V1[1],
    CATALOG_V1[2],
    CATALOG_V1[3],
    ServiceDefinition {
        id: "netflix",
        name: "Netflix",
        category: "Video",
        suffixes: &["netflix.com"],
        exact_names: &[],
        limitations: &[
            "Website/account/API names only. Separate streaming CDNs and existing playback are not covered.",
        ],
        references: &["https://help.netflix.com/en/node/114701/"],
    },
    ServiceDefinition {
        id: "spotify",
        name: "Spotify",
        category: "Music",
        suffixes: &["spotify.com"],
        exact_names: &[],
        limitations: &[
            "Website/API/embed names only. Separate audio/image CDNs and existing streams are not covered.",
        ],
        references: &[
            "https://developer.spotify.com/documentation/embeds/tutorials/using-the-iframe-api",
        ],
    },
    ServiceDefinition {
        id: "twitch",
        name: "Twitch",
        category: "Video",
        suffixes: &["twitch.tv"],
        exact_names: &[],
        limitations: &[
            "Website/player/chat names only. Independent media/CDN domains and existing streams are not covered.",
        ],
        references: &["https://dev.twitch.tv/docs/embed/video-and-clips/"],
    },
    ServiceDefinition {
        id: "steam",
        name: "Steam",
        category: "Gaming",
        suffixes: &["steampowered.com", "steamcommunity.com", "steamstatic.com"],
        exact_names: &[],
        limitations: &[
            "Includes store/community/support/API and static assets. Game servers, independent downloads and other Valve services are not comprehensively covered.",
        ],
        references: &[
            "https://partner.steamgames.com/doc/webapi_overview",
            "https://steamcommunity.com/",
        ],
    },
    ServiceDefinition {
        id: "roblox",
        name: "Roblox",
        category: "Gaming",
        suffixes: &["roblox.com"],
        exact_names: &[],
        limitations: &[
            "Website/API names only. Separate assets, game transports and existing sessions are not comprehensively covered.",
        ],
        references: &["https://create.roblox.com/docs/cloud/reference/domains/apis"],
    },
    ServiceDefinition {
        id: "whatsapp",
        name: "WhatsApp",
        category: "Messaging",
        suffixes: &["whatsapp.com", "whatsapp.net"],
        exact_names: &[],
        limitations: &[
            "Includes website and documented network domain. Calls, established sessions and non-DNS traffic are not guaranteed blocked.",
        ],
        references: &["https://faq.whatsapp.com/852892549070029/?cms_platform=web&helpref=hc_fnav"],
    },
    ServiceDefinition {
        id: "telegram",
        name: "Telegram",
        category: "Messaging",
        suffixes: &["telegram.org", "t.me"],
        exact_names: &[],
        limitations: &[
            "Includes web/API and public links. Existing sessions and non-DNS transports may continue.",
        ],
        references: &["https://telegram.org/faq"],
    },
    ServiceDefinition {
        id: "signal",
        name: "Signal",
        category: "Messaging",
        suffixes: &["signal.org"],
        exact_names: &[],
        limitations: &[
            "Includes documented Signal domain and its subdomains. Established sessions and non-DNS call traffic may continue.",
        ],
        references: &[
            "https://support.signal.org/hc/en-us/articles/360007320291-Firewall-and-Internet-settings",
        ],
    },
];
impl PolicyConfig {
    /// Expand frozen service selections into ordinary immutable filter inputs.
    /// Use this same expansion for historical rule IDs. Disabled inputs are
    /// borrowed; enabled inputs own a bounded copy. Keep this off DNS executors.
    pub fn filter_inputs(&self) -> Result<Cow<'_, [ListInput]>, PolicyError> {
        self.filter_inputs_for_services(true)
    }
    /// Expand the specified recorded service variant without consulting wall time.
    pub fn filter_inputs_for_services(
        &self,
        active: bool,
    ) -> Result<Cow<'_, [ListInput]>, PolicyError> {
        if self.lists.iter().any(|list| list.name.starts_with(PREFIX)) {
            return Err(PolicyError::field(
                "lists.name",
                "@service/ is reserved for built-in provenance",
            ));
        }
        let Some(settings) = &self.blocked_services else {
            return Ok(Cow::Borrowed(&self.lists));
        };
        let catalog = service_catalog_for_version(settings.catalog_version)?;
        PolicyError::check_count(
            || "blocked_services.ids".into(),
            settings.ids.len(),
            0,
            catalog.len(),
        )?;
        let mut selected = HashSet::new();
        for id in &settings.ids {
            if !catalog.iter().any(|service| service.id == id) {
                return Err(PolicyError::field(
                    "blocked_services.ids",
                    "unknown service ID",
                ));
            }
            if !selected.insert(id.as_str()) {
                return Err(PolicyError::field(
                    "blocked_services.ids",
                    "duplicate service ID",
                ));
            }
        }
        if settings.schedule.is_some() && selected.is_empty() {
            return Err(PolicyError::field(
                "blocked_services.schedule",
                "select a service before configuring its schedule",
            ));
        }
        if let Some(schedule) = &settings.schedule {
            schedule.validate()?;
        }
        if selected.is_empty() || !active {
            return Ok(Cow::Borrowed(&self.lists));
        }
        let mut inputs = self.lists.clone();
        for service in catalog
            .iter()
            .filter(|service| selected.contains(service.id))
        {
            let mut rules = String::new();
            for (exact, names) in [(false, service.suffixes), (true, service.exact_names)] {
                for domain in names {
                    let normalized = rustwalld_dns_filter::normalize(domain)?;
                    if normalized != *domain {
                        return Err(PolicyError::field(
                            "blocked_services",
                            "noncanonical built-in service domain",
                        ));
                    }
                    if exact {
                        rules.push('=');
                    }
                    rules.push_str(domain);
                    rules.push('\n');
                }
            }
            inputs.push(ListInput {
                name: format!(
                    "{PREFIX}v{}/{} ({})",
                    settings.catalog_version, service.id, service.name
                ),
                action: Action::Block,
                syntax: RuleSyntax::Native,
                rules,
            });
        }
        Ok(Cow::Owned(inputs))
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{Assertion, PolicyConfigSet, PolicySnapshot};
    use std::sync::Arc;
    fn config(ids: &[&str]) -> PolicyConfigSet {
        let mut config = PolicyConfigSet::default();
        config.policies[0].blocked_services = Some(BlockedServices {
            catalog_version: 1,
            ids: ids.iter().map(|s| (*s).to_owned()).collect(),
            schedule: None,
        });
        config
    }
    #[test]
    fn original_catalog_defaults_wire_shape_and_generated_content_are_frozen() {
        let input: BlockedServices = serde_json::from_str(r#"{"ids":["youtube"]}"#).unwrap();
        assert_eq!(input.catalog_version, 1);
        assert_eq!(service_catalog().len(), 4);
        assert!(service_catalog_for_version(0).is_err());
        assert!(service_catalog_for_version(3).is_err());
        let wire = serde_json::to_value(service_catalog()).unwrap();
        assert!(
            wire.as_array()
                .unwrap()
                .iter()
                .all(|item| item.as_object().unwrap().len() == 5)
        );
        let configured = config(&["youtube"]);
        let lists = configured.policies[0].filter_inputs().unwrap();
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].name, "@service/v1/youtube (YouTube)");
        assert_eq!(
            lists[0].rules,
            "youtube.com\nyoutu.be\nyoutube-nocookie.com\n=youtube.googleapis.com\n=youtubei.googleapis.com\n"
        );
        let one = service_catalog();
        let two = service_catalog_for_version(2).unwrap();
        for (old, new) in one.iter().zip(two) {
            assert_eq!(
                serde_json::to_value(old).unwrap(),
                serde_json::to_value(new).unwrap()
            );
        }
    }
    #[test]
    fn expanded_catalog_is_canonical_bounded_and_filters_every_group_without_shared_clouds() {
        let catalog = service_catalog_for_version(2).unwrap();
        assert_eq!(catalog.len(), 12);
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        let mut configured = config(&[]);
        let settings = configured.policies[0].blocked_services.as_mut().unwrap();
        settings.catalog_version = 2;
        settings.ids = catalog.iter().map(|group| group.id.into()).collect();
        for group in catalog {
            assert!(ids.insert(group.id));
            assert!(group.id.bytes().all(|byte| byte.is_ascii_lowercase()));
            for name in group.suffixes.iter().chain(group.exact_names) {
                assert_eq!(rustwalld_dns_filter::normalize(name).unwrap(), *name);
                assert!(names.insert(*name));
            }
            for link in group.references {
                assert!(link.starts_with("https://"));
            }
        }
        assert_eq!(names.len(), 21);
        let snapshot = PolicySnapshot::compile(configured, 1).unwrap();
        for group in catalog {
            for name in group.suffixes {
                for domain in [name.to_string(), format!("deep.sub.{name}")] {
                    let trace = snapshot
                        .explain("127.0.0.1".parse().unwrap(), &domain)
                        .unwrap();
                    assert_eq!(trace.decision.action, Action::Block);
                    assert!(trace.rule.unwrap().sources.iter().any(|source| {
                        source
                            .list
                            .starts_with(&format!("@service/v2/{} ", group.id))
                    }));
                }
                assert_eq!(
                    snapshot.policies()[0]
                        .filters()
                        .evaluate(&format!("not{name}"))
                        .action,
                    Action::Allow
                );
            }
        }
        for neighbor in [
            "amazonaws.com",
            "cloudfront.net",
            "google.com",
            "googleapis.com",
            "fastly.net",
            "notsteamcommunity.com",
            "notwhatsapp.net",
        ] {
            assert_eq!(
                snapshot.policies()[0].filters().evaluate(neighbor).action,
                Action::Allow
            );
        }
    }
    #[test]
    fn version_validation_schedule_variants_and_native_allow_keep_provenance() {
        let mut configured = config(&["netflix"]);
        assert!(PolicySnapshot::compile(configured.clone(), 1).is_err());
        let settings = configured.policies[0].blocked_services.as_mut().unwrap();
        settings.catalog_version = 2;
        settings.schedule = Some(crate::WeeklySchedule {
            time_zone: "UTC".into(),
            mode: crate::ScheduleMode::Block,
            windows: vec![],
        });
        configured.policies[0].lists.push(ListInput {
            name: "manual".into(),
            action: Action::Block,
            syntax: RuleSyntax::Native,
            rules: "=manual.netflix.com".into(),
        });
        configured.policies[0].lists.push(ListInput {
            name: "support".into(),
            action: Action::Allow,
            syntax: RuleSyntax::Native,
            rules: "=help.netflix.com".into(),
        });
        let snapshot = PolicySnapshot::compile(configured.clone(), 1).unwrap();
        let policy = &snapshot.policies()[0];
        assert_eq!(
            policy
                .filters_for_services(true)
                .evaluate("www.netflix.com")
                .action,
            Action::Block
        );
        assert_eq!(
            policy
                .filters_for_services(false)
                .evaluate("www.netflix.com")
                .action,
            Action::Allow
        );
        for active in [true, false] {
            let filters = policy.filters_for_services(active);
            assert_eq!(filters.evaluate("help.netflix.com").action, Action::Allow);
            assert_eq!(filters.evaluate("manual.netflix.com").action, Action::Block);
            let inputs = configured.policies[0]
                .filter_inputs_for_services(active)
                .unwrap();
            let reconstructed =
                rustwalld_dns_filter::FilterSnapshot::compile(&inputs, 1000, 10000).unwrap();
            let decision = filters.evaluate("manual.netflix.com");
            assert_eq!(decision, reconstructed.evaluate("manual.netflix.com"));
            assert_eq!(
                filters.rule(decision.rule.unwrap()).unwrap().sources.len(),
                1
            );
        }
        configured.policies[0]
            .blocked_services
            .as_mut()
            .unwrap()
            .ids
            .push("netflix".into());
        assert!(PolicySnapshot::compile(configured, 2).is_err());
    }
    #[test]
    fn catalog_coverage_allow_precedence_and_assertions() {
        let mut config = config(&["youtube", "discord", "reddit", "tiktok"]);
        config.policies[0].lists.push(ListInput {
            name: "allow".into(),
            action: Action::Allow,
            syntax: RuleSyntax::Native,
            rules: "=support.discord.com".into(),
        });
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        for name in [
            "www.youtube.com",
            "youtu.be",
            "youtubei.googleapis.com",
            "www.tiktok.com",
            "old.reddit.com",
            "discord.gg",
        ] {
            let trace = snapshot
                .explain("127.0.0.1".parse().unwrap(), name)
                .unwrap();
            assert_eq!(trace.decision.action, Action::Block);
            assert!(
                trace
                    .rule
                    .unwrap()
                    .sources
                    .iter()
                    .any(|source| source.list.starts_with(PREFIX))
            );
        }
        for name in [
            "support.discord.com",
            "google.com",
            "googleapis.com",
            "sub.youtubei.googleapis.com",
            "notyoutube.com",
            "googlevideo.com",
            "tiktokcdn.com",
        ] {
            assert_eq!(
                snapshot
                    .explain("127.0.0.1".parse().unwrap(), name)
                    .unwrap()
                    .decision
                    .action,
                Action::Allow
            );
        }
        config.assertions.push(Assertion {
            qtype: 1,
            client: "127.0.0.1".parse().unwrap(),
            domain: "www.youtube.com".into(),
            expected: Action::Allow,
        });
        assert!(PolicySnapshot::compile(config, 2).is_err());
    }
    #[test]
    fn canonical_order_shares_and_history_reconstructs_rule_ids() {
        let mut config = config(&["youtube", "discord"]);
        let mut other = config.policies[0].clone();
        other.name = "other".into();
        other.blocked_services.as_mut().unwrap().ids.reverse();
        config.policies.push(other);
        let snapshot = PolicySnapshot::compile(config, 1).unwrap();
        assert!(Arc::ptr_eq(
            &snapshot.policies()[0].filters,
            &snapshot.policies()[1].filters
        ));
        let trace = snapshot
            .explain("127.0.0.1".parse().unwrap(), "www.youtube.com")
            .unwrap();
        let inputs = snapshot.config().policies[0].filter_inputs().unwrap();
        let rebuilt = rustwalld_dns_filter::FilterSnapshot::compile(&inputs, 10000, 10000).unwrap();
        assert_eq!(
            rebuilt.rule(trace.decision.rule.unwrap()).unwrap().domain,
            trace.rule.unwrap().domain
        );
        assert!(snapshot.config().policies[0].lists.is_empty());
    }
    #[cfg(feature = "parallel")]
    #[test]
    fn service_rule_ids_and_provenance_match_parallel_compilation() {
        let mut config = config(&["youtube", "tiktok"]);
        config.policies[0].lists.push(ListInput {
            name: "large".into(),
            action: Action::Block,
            syntax: RuleSyntax::Native,
            rules: (0..40000)
                .map(|index| format!("=n{index}.test\n"))
                .collect(),
        });
        let serial = PolicySnapshot::compile(config.clone(), 1).unwrap();
        let pool = rustwalld_dns_filter::ParallelCompiler::new(2).unwrap();
        let parallel = PolicySnapshot::compile_parallel(config, 2, &pool).unwrap();
        for domain in ["www.youtube.com", "www.tiktok.com", "n30000.test"] {
            let one = serial
                .explain("127.0.0.1".parse().unwrap(), domain)
                .unwrap();
            let two = parallel
                .explain("127.0.0.1".parse().unwrap(), domain)
                .unwrap();
            assert_eq!(one.decision.rule, two.decision.rule);
            assert_eq!(one.rule.unwrap().domain, two.rule.unwrap().domain);
            assert_eq!(
                one.rule
                    .unwrap()
                    .sources
                    .iter()
                    .map(|source| (&source.list, source.line))
                    .collect::<Vec<_>>(),
                two.rule
                    .unwrap()
                    .sources
                    .iter()
                    .map(|source| (&source.list, source.line))
                    .collect::<Vec<_>>(),
            );
        }
        // Scheduled on/off variants must retain identical IDs and provenance
        // through both compilers, including the large ordinary list when off.
        let mut configured = serial.config().clone();
        configured.policies[0]
            .blocked_services
            .as_mut()
            .unwrap()
            .catalog_version = 2;
        configured.policies[0]
            .blocked_services
            .as_mut()
            .unwrap()
            .schedule = Some(crate::WeeklySchedule {
            time_zone: "UTC".into(),
            mode: crate::ScheduleMode::Block,
            windows: vec![],
        });
        let scheduled_serial = PolicySnapshot::compile(configured.clone(), 3).unwrap();
        let scheduled_parallel = PolicySnapshot::compile_parallel(configured, 4, &pool).unwrap();
        for active in [false, true] {
            let one = scheduled_serial.policies()[0].filters_for_services(active);
            let two = scheduled_parallel.policies()[0].filters_for_services(active);
            for domain in ["www.youtube.com", "www.tiktok.com", "n30000.test"] {
                let decision = one.evaluate(domain);
                assert_eq!(decision, two.evaluate(domain));
                if let Some(id) = decision.rule {
                    let left = one.rule(id).unwrap();
                    let right = two.rule(id).unwrap();
                    assert_eq!(left.domain, right.domain);
                    assert_eq!(
                        left.sources
                            .iter()
                            .map(|source| (&source.list, source.line))
                            .collect::<Vec<_>>(),
                        right
                            .sources
                            .iter()
                            .map(|source| (&source.list, source.line))
                            .collect::<Vec<_>>()
                    );
                }
                if !active && domain != "n30000.test" {
                    assert_eq!(decision.action, Action::Allow);
                    assert!(decision.rule.is_none());
                }
            }
        }
    }
    #[test]
    fn rejects_unknown_duplicate_catalog_and_forged_provenance_even_when_disabled() {
        for ids in [
            vec!["unknown"],
            vec!["youtube", "youtube"],
            vec!["youtube", "reddit", "discord", "tiktok", "youtube"],
        ] {
            assert!(PolicySnapshot::compile(config(&ids), 1).is_err());
        }
        let mut config = config(&[]);
        config.policies[0]
            .blocked_services
            .as_mut()
            .unwrap()
            .catalog_version = 3;
        assert!(PolicySnapshot::compile(config.clone(), 1).is_err());
        config.policies[0].blocked_services = None;
        config.policies[0].lists.push(ListInput {
            name: "@service/v1/youtube (forged)".into(),
            action: Action::Block,
            rules: "example.test".into(),
            syntax: RuleSyntax::Native,
        });
        assert!(PolicySnapshot::compile(config, 1).is_err());
    }
}
