//! Offline, bounded migration into an editable policy draft. Never publishes.
mod adguard;
mod archive;
mod client_upstreams;
mod pattern_rewrites;
mod pihole;
mod pihole_v5;
mod safe_search;
mod service_schedule;
mod services;
mod upstreams;
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{
    CheckReport, PolicyConfig, PolicyConfigSet, PolicySnapshot, UpstreamProfile, UpstreamTransport,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};
/// Maximum compressed/raw upload accepted by the migration adapter.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_EXPANDED_BYTES: usize = 64 * 1024 * 1024;
const MAX_ISSUES: usize = 200;
/// Source application; Pi-hole accepts v5/v6 Teleporter exports or gravity.db.
#[derive(Clone, Copy, Debug, clap::ValueEnum, serde::Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Pi-hole v5/v6 Teleporter or gravity database.
    Pihole,
    /// AdGuard Home YAML/JSON configuration.
    Adguard,
}
/// Severity of an untranslated or intentionally different setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Activation cannot claim source-equivalent behavior.
    Blocker,
    /// Requires operator review but does not invalidate translated rules.
    Warning,
    /// Informational boundary.
    Info,
}
/// One bounded compatibility diagnostic. Source credentials are never included.
#[derive(Debug, Serialize)]
pub struct Issue {
    /// Source field/file path, not its secret value.
    pub field: String,
    /// Severity.
    pub severity: Severity,
    /// Operator explanation.
    pub message: String,
}
/// Publisher reference requiring explicit review/bootstrap configuration.
#[derive(Debug, Serialize)]
pub struct Publisher {
    /// Destination policy.
    pub policy: String,
    /// Destination list.
    pub list: String,
    /// Publisher URL; never fetched by import.
    pub url: String,
    /// List action.
    pub action: Action,
    /// Source backup did not include its contents.
    pub needs_download: bool,
}
/// A draft and complete accounting of migration limitations.
#[derive(Serialize)]
pub struct Report {
    /// Source application.
    pub source: Source,
    /// Translated policy configuration; not published.
    pub config: PolicyConfigSet,
    /// Bounded detailed diagnostics.
    pub issues: Vec<Issue>,
    /// Total diagnostics, including truncated details.
    pub total_issues: usize,
    /// Number of blockers, including truncated details.
    pub blockers: usize,
    /// Whether the draft compiled and satisfies required assertions.
    pub validation: Option<CheckReport>,
    /// Number of translated rules before compilation.
    pub translated_rules: usize,
    /// Whether source-equivalent activation can be reviewed.
    pub ready: bool,
    /// Publisher references retained for the reviewed download workflow.
    pub publishers: Vec<Publisher>,
}
impl Report {
    /// Include the destination's admission/self-forwarding checks in readiness.
    /// This is pure validation; it does not bind a listener or publish the draft.
    pub fn validate_listener(&mut self, listen: SocketAddr) {
        if let Err(error) = crate::config::validate_policy(&self.config, listen) {
            self.issue("resolver", Severity::Blocker, error);
            self.ready = false;
        }
    }
    fn new(source: Source, mut base: PolicyConfigSet) -> Self {
        // Keep listener admission/assertions and an explicitly configured resolver.
        // Source settings are imported below, or reported without silent changes.
        base.filter_sources.clear();
        Self {
            source,
            config: base,
            issues: vec![],
            total_issues: 0,
            blockers: 0,
            validation: None,
            translated_rules: 0,
            ready: false,
            publishers: vec![],
        }
    }
    pub(super) fn issue(
        &mut self,
        field: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
    ) {
        self.total_issues += 1;
        if severity == Severity::Blocker {
            self.blockers += 1;
        }
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(Issue {
                field: field.into().chars().take(256).collect(),
                severity,
                message: message.into(),
            });
        }
    }
    pub(super) fn unreviewed(
        &mut self,
        value: &serde_json::Value,
        path: &str,
        handled: &[&str],
        operational: &[&str],
    ) {
        if let Some(object) = value.as_object() {
            for key in object.keys() {
                if !handled.contains(&key.as_str()) {
                    self.issue(format!("{path}.{key}"),if operational.contains(&key.as_str()) {Severity::Warning} else {Severity::Blocker},"Setting was not translated. Review its destination equivalent explicitly; source values and credentials are omitted.");
                }
            }
        }
    }
    pub(super) fn policy(&self, name: String) -> PolicyConfig {
        PolicyConfig {
            name,
            upstream: self.config.upstreams[0].name.clone(),
            lists: vec![],
            rewrites: vec![],
            temporary_exceptions: vec![],
            dns_records: vec![],
            routes: vec![],
            ds_routing: Default::default(),
            block_mode: Default::default(),
            safe_search: None,
            blocked_services: None,
        }
    }
    pub(super) fn rules(
        &mut self,
        policy: &mut PolicyConfig,
        name: String,
        action: Action,
        rules: String,
    ) {
        let retained = policy
            .lists
            .iter()
            .map(|list| list.rules.len())
            .sum::<usize>();
        if retained.saturating_add(rules.len()) > MAX_EXPANDED_BYTES {
            self.issue(
                "filters",
                Severity::Blocker,
                "Combined imported rule text exceeds 64 MiB; list was not included.",
            );
            return;
        }
        self.translated_rules += rules.lines().filter(|line| !line.trim().is_empty()).count();
        if !rules.is_empty() {
            policy.lists.push(ListInput {
                syntax: match self.source {
                    Source::Adguard => rustwalld_dns_filter::RuleSyntax::AdguardV6,
                    Source::Pihole => rustwalld_dns_filter::RuleSyntax::Native,
                },
                name,
                action,
                rules,
            });
        }
    }
    pub(super) fn literal_upstreams(&mut self, values: &[String], field: &str) {
        if values.is_empty() {
            return;
        }
        let mut addresses = Vec::new();
        for (index, value) in values.iter().enumerate() {
            if let Some(address) = literal_address(value) {
                addresses.push(address);
            } else {
                self.issue(format!("{field}[{index}]"),Severity::Blocker,"Hostname/encrypted/domain-specific upstream needs an explicit profile and bootstrap IPs; the existing resolver is retained until reviewed.");
            }
        }
        if !addresses.is_empty() && addresses.len() == values.len() && addresses.len() <= 8 {
            self.config.upstreams = vec![UpstreamProfile {
                name: "imported-resolver".into(),
                addresses,
                timeout_ms: 1500,
                transport: UpstreamTransport::Udp,
            }];
        } else if addresses.len() > 8 {
            self.issue(
                field,
                Severity::Blocker,
                "More than eight upstream addresses require splitting into profiles.",
            );
        }
    }
    fn finish(mut self) -> Self {
        for publisher in &self.publishers {
            if publisher.needs_download
                && let Some(policy) = self
                    .config
                    .policies
                    .iter_mut()
                    .find(|policy| policy.name == publisher.policy)
                && !policy.lists.iter().any(|list| list.name == publisher.list)
            {
                policy.lists.push(ListInput {
                    name: publisher.list.clone(),
                    action: publisher.action,
                    rules: String::new(),
                    syntax: match self.source {
                        Source::Adguard => rustwalld_dns_filter::RuleSyntax::AdguardV6,
                        Source::Pihole => rustwalld_dns_filter::RuleSyntax::Native,
                    },
                });
            }
        }
        match PolicySnapshot::check(self.config.clone()) {
            Ok(check) => {
                if !check.valid {
                    self.issue("assertions",Severity::Blocker,"Existing required assertions failed. Review the draft without weakening protection silently.");
                }
                self.validation = Some(check);
            }
            Err(error) => self.issue("draft", Severity::Blocker, error.to_string()),
        }
        self.ready =
            self.blockers == 0 && self.validation.as_ref().is_some_and(|check| check.valid);
        self
    }
}
/// Parse an uploaded source configuration without network, database publication
/// or service activation. Call on a bounded blocking control-plane worker.
pub fn preview(source: Source, input: &[u8], base: PolicyConfigSet) -> Result<Report, String> {
    if input.is_empty() || input.len() > MAX_INPUT_BYTES {
        return Err("migration input must contain 1..16 MiB".into());
    }
    if base.upstreams.is_empty() {
        return Err("base configuration needs an existing resolver profile".into());
    }
    let mut report = Report::new(source, base);
    match source {
        Source::Adguard => adguard::import(input, &mut report)?,
        Source::Pihole => pihole::import(input, &mut report)?,
    }
    Ok(report.finish())
}
pub(super) fn literal_address(input: &str) -> Option<SocketAddr> {
    if let Some((host, port)) = input.rsplit_once('#') {
        return Some(SocketAddr::new(host.parse().ok()?, port.parse().ok()?));
    }
    input.parse::<SocketAddr>().ok().or_else(|| {
        input
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}
pub(super) fn booleans(
    value: &serde_json::Value,
    path: &str,
    fields: &[&str],
) -> Result<(), String> {
    for field in fields {
        if let Some(value) = value.get(*field)
            && !value.is_null()
            && !value.is_boolean()
        {
            return Err(format!("{path}.{field} must be a boolean"));
        }
    }
    Ok(())
}
fn publisher_url(value: &str) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|_| "Invalid publisher URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "Publisher URL must use HTTP(S), without embedded credentials or fragment".into(),
        );
    }
    Ok(url.to_string())
}
pub(super) fn yaml(input: &[u8]) -> Result<serde_json::Value, String> {
    let mut budget = serde_saphyr::Budget::default();
    budget.max_documents = 1;
    budget.max_depth = 32;
    budget.flow_nesting_limit = 32;
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_nodes = 250000;
    budget.max_events = 750000;
    budget.max_total_scalar_bytes = MAX_INPUT_BYTES;
    budget.max_reader_input_bytes = Some(MAX_INPUT_BYTES);
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options.emit_comments = false;
    options.with_snippet = false;
    options.reject_unsupported_tags = true;
    options.merge_keys = serde_saphyr::options::MergeKeyPolicy::Error;
    serde_saphyr::from_slice_with_options(input,options).map_err(|_|"Invalid YAML/JSON, duplicate keys, unsupported tags/aliases or migration parser budget exceeded".into())
}
pub(super) fn string(value: &serde_json::Value) -> Option<String> {
    value.as_str().map(ToOwned::to_owned)
}
pub(super) fn array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a [serde_json::Value], String> {
    if value.is_null() {
        Ok(&[])
    } else {
        value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| format!("{field} must be an array"))
    }
}
pub(super) fn string_array(value: &serde_json::Value, field: &str) -> Result<Vec<String>, String> {
    array(value, field)?
        .iter()
        .map(|value| string(value).ok_or_else(|| format!("{field} entries must be strings")))
        .collect()
}
pub(super) type Files = BTreeMap<String, Vec<u8>>;
