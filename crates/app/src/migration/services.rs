//! Reviewed subset of AdGuard service selections. No catalog is downloaded.
use super::{Report, Severity, string_array};
use rustwalld_dns_policy::{
    BlockedServices, LATEST_SERVICE_CATALOG_VERSION, service_catalog_for_version,
};
use serde_json::Value;
/// Validate even ignored client values before considering inheritance.
pub(super) fn validate(value: &Value, path: &str) -> Result<Vec<String>, String> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let ids = if value.is_array() {
        value
    } else if value.is_object() {
        super::service_schedule::validate(&value["schedule"], &format!("{path}.schedule"))?;
        &value["ids"]
    } else {
        return Err(format!("{path} must be a list or mapping"));
    };
    let ids = string_array(ids, path)?;
    if ids.len() > 256 {
        return Err(format!("{path} exceeds 256 service IDs"));
    }
    Ok(ids)
}
pub(super) fn translate(
    value: &Value,
    path: &str,
    report: &mut Report,
    json_source: bool,
) -> Result<Option<BlockedServices>, String> {
    let ids = validate(value, path)?;
    if value.is_object() {
        report.unreviewed(value, path, &["ids", "schedule"], &[]);
        if value.get("ids").is_none() || value["ids"].is_null() {
            report.issue(
                format!("{path}.ids"),
                Severity::Blocker,
                "Source service IDs are absent; no service defaults were guessed.",
            );
        }
    }
    let catalog = service_catalog_for_version(LATEST_SERVICE_CATALOG_VERSION)
        .map_err(|error| error.to_string())?;
    let mut supported = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        if !catalog.iter().any(|service| service.id == id) {
            report.issue(format!("{path}.ids[{index}]"), Severity::Blocker, "Unsupported source service ID has no destination coverage; it was not silently ignored.");
        } else if supported.contains(id) {
            report.issue(
                format!("{path}.ids[{index}]"),
                Severity::Blocker,
                "Duplicate source service ID needs review.",
            );
        } else {
            supported.push(id.clone());
        }
    }
    let schedule = super::service_schedule::translate(
        &value["schedule"],
        &format!("{path}.schedule"),
        json_source,
        report,
    )?;
    if supported.is_empty() {
        return Ok(None);
    }
    report.issue(path, Severity::Blocker, "Destination catalog v2 has explicitly limited first-party domain coverage and native allow/local/temporary overrides. Review and extend coverage before claiming AdGuard-equivalent service blocking.");
    Ok(Some(BlockedServices {
        catalog_version: LATEST_SERVICE_CATALOG_VERSION,
        ids: supported,
        schedule,
    }))
}
