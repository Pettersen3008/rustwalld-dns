//! Explicit AdGuard provider choices; ambiguous defaults remain blockers.
use super::{Report, Severity};
use rustwalld_dns_policy::{SafeSearchConfig, YouTubeMode};
use serde_json::Value;
const PROVIDERS: &[&str] = &[
    "google",
    "bing",
    "duckduckgo",
    "youtube",
    "yandex",
    "pixabay",
    "ecosia",
];
pub(super) fn validate(value: &Value, path: &str) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    if !value.is_object() {
        return Err(format!("{path}.safe_search must be a mapping"));
    }
    super::booleans(
        value,
        &format!("{path}.safe_search"),
        &[
            "enabled",
            "google",
            "bing",
            "duckduckgo",
            "youtube",
            "yandex",
            "pixabay",
            "ecosia",
        ],
    )
}
pub(super) fn translate(
    value: &Value,
    path: &str,
    report: &mut Report,
) -> Result<Option<SafeSearchConfig>, String> {
    let settings = &value["safe_search"];
    validate(settings, path)?;
    if settings.is_null() {
        if value["safesearch_enabled"].as_bool() == Some(true) {
            report.issue(format!("{path}.safesearch_enabled"),Severity::Blocker,"Legacy SafeSearch enablement does not identify provider coverage; choose explicit destination provider settings.");
        }
        return Ok(None);
    }
    let field = format!("{path}.safe_search");
    report.unreviewed(
        settings,
        &field,
        &[
            "enabled",
            "google",
            "bing",
            "duckduckgo",
            "youtube",
            "yandex",
            "pixabay",
            "ecosia",
        ],
        &[],
    );
    match settings["enabled"].as_bool() {
        Some(false) => return Ok(None),
        None => {
            report.issue(
                format!("{field}.enabled"),
                Severity::Blocker,
                "SafeSearch enablement is absent; source defaults were not guessed.",
            );
            return Ok(None);
        }
        Some(true) => {}
    }
    for provider in PROVIDERS {
        if settings[*provider].as_bool().is_none() {
            report.issue(format!("{field}.{provider}"),Severity::Blocker,"Source provider flag is absent; its version-specific default cannot be assumed disabled.");
        }
    }
    for provider in ["yandex", "pixabay", "ecosia"] {
        if settings[provider].as_bool() == Some(true) {
            report.issue(format!("{field}.{provider}"),Severity::Blocker,"This provider has no supported destination enforcement catalog; it was not silently disabled.");
        }
    }
    let config = SafeSearchConfig {
        google: settings["google"].as_bool() == Some(true),
        bing: settings["bing"].as_bool() == Some(true),
        duckduckgo: settings["duckduckgo"].as_bool() == Some(true),
        youtube: if settings["youtube"].as_bool() == Some(true) {
            YouTubeMode::Moderate
        } else {
            YouTubeMode::Off
        },
        ..Default::default()
    };
    if !config.is_disabled() {
        report.issue(field,Severity::Warning,"Supported providers use the frozen destination CNAME catalog. YouTube imports as Moderate; destination CNAME enforcement also covers other accepted DNS types. Review provider coverage and resolver routing before activation.");
    }
    Ok((!config.is_disabled()).then_some(config))
}
