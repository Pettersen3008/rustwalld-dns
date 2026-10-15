//! Offline conversion of a bounded literal custom/bundled rewrite subset.
//! This is not a new native list interpreter or DNS executor parser.
mod responses;
use super::{Report, Severity};
use responses::Response;
use rustwalld_dns_policy::{LocalData, LocalRecord};
use serde_json::Value;
use std::collections::HashMap;

const MAX_DECLARATIONS: usize = 512;
const MAX_PATTERNS: usize = 256;
const MAX_LINE_BYTES: usize = 4096;
pub(super) struct Pattern {
    domain: String,
    descendants: bool,
    response: Option<Response>,
    exception: bool,
    field: String,
}
#[derive(Default)]
pub(super) struct Extractor {
    pub(super) present: bool,
    patterns: Vec<Pattern>,
    declarations: usize,
    invalid: bool,
}
fn parse(line: &str, field: String) -> Result<Pattern, &'static str> {
    let trailing_whitespace = line.trim_end().len() != line.len();
    let line = line.trim_end();
    let (line, exception) = line
        .strip_prefix("@@")
        .map_or((line, false), |line| (line, true));
    let (mask, modifier) = line.split_once("$dnsrewrite").ok_or(
        "Only supported literal rewrites and same-pattern exceptions without additional modifiers are supported.",
    )?;
    let value = if exception && modifier.is_empty() {
        ""
    } else {
        modifier.strip_prefix('=').ok_or("Rewrite modifiers require a literal address or a bare exception without additional options.")?
    };
    let (domain, descendants) = if let Some(mask) = mask.strip_prefix("||") {
        (mask.strip_suffix('^'), true)
    } else if let Some(mask) = mask.strip_prefix('|') {
        (
            mask.strip_suffix('^').or_else(|| mask.strip_suffix('|')),
            false,
        )
    } else {
        (None, false)
    };
    let domain = domain.ok_or(
        "Rewrite patterns require explicit exact |name^ / |name| or suffix ||name^ anchors.",
    )?;
    if !domain.is_ascii() || domain.ends_with('.') || domain.chars().any(char::is_whitespace) {
        return Err(
            "Source rewrite patterns must be ASCII without whitespace or a trailing root dot; normalization could change coverage.",
        );
    }
    let domain = rustwalld_dns_filter::normalize(domain)
        .map_err(|_| "Unsupported literal rewrite name or pattern.")?;
    let response = if exception && value.is_empty() {
        None
    } else {
        Some(Response::parse(value, exception)?)
    };
    if response.as_ref().is_some_and(|value| !value.is_address()) && trailing_whitespace {
        return Err(
            "Non-address rewrite responses require no trailing source-line whitespace; normalization behavior needs review.",
        );
    }
    Ok(Pattern {
        domain,
        descendants,
        response,
        exception,
        field,
    })
}
pub(super) fn candidate(raw: &str) -> bool {
    let line = raw.trim();
    if line.starts_with(['#', '!']) || !line.contains("dnsrewrite") {
        return false;
    }
    let rule = line.strip_prefix("@@").unwrap_or(line);
    // A whole regex may contain dollar anchors and the literal word dnsrewrite.
    // It has no modifier section. For regexes with options, select the last
    // unescaped dollar outside quoted values; literal masks use the first.
    let regex = rule.starts_with('/');
    // A regex response value may itself end with '/', so it must not be
    // mistaken for a whole ordinary regex. Ambiguous rewrite-like regex
    // option text is conservatively retained as an unsupported candidate.
    if regex
        && rule
            .split("/$")
            .skip(1)
            .any(|options| options.starts_with("dnsrewrite") || options.contains(",dnsrewrite"))
    {
        return true;
    }
    if regex && rule.ends_with('/') {
        return false;
    }
    let mut quote = None;
    let mut escaped = false;
    let mut delimiter = None;
    for (index, byte) in rule.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        if let Some(current) = quote {
            if byte == current {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'$' {
            delimiter = Some(index);
            if !regex {
                break;
            }
        }
    }
    let Some(delimiter) = delimiter else {
        return false;
    };
    let modifiers = &rule[delimiter + 1..];
    let token = |value: &str| value == "dnsrewrite" || value.starts_with("dnsrewrite=");
    quote = None;
    escaped = false;
    let mut start = 0;
    for (index, byte) in modifiers.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        if let Some(current) = quote {
            if byte == current {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b',' {
            if token(&modifiers[start..index]) {
                return true;
            }
            start = index + 1;
        }
    }
    token(&modifiers[start..])
}
impl Extractor {
    pub(super) fn invalidate(&mut self) {
        self.invalid = true;
    }
    pub(super) fn finish(self) -> Vec<Pattern> {
        if self.invalid {
            Vec::new()
        } else {
            self.patterns
        }
    }
    pub(super) fn user_rules(
        &mut self,
        rules: &[String],
        active: bool,
        report: &mut Report,
    ) -> String {
        let mut ordinary = String::new();
        for (index, entry) in rules.iter().enumerate() {
            ordinary.push_str(
                &self
                    .scan(entry, &format!("user_rules[{index}]"), true, active, report)
                    .0,
            );
        }
        if self.present && !active {
            report.issue("user_rules",Severity::Info,"Source filtering is disabled; pattern rewrite rules were omitted without activating local records.");
        }
        ordinary
    }
    pub(super) fn feed(&mut self, text: &str, path: &str, report: &mut Report) -> (String, bool) {
        self.scan(text, path, false, true, report)
    }
    fn scan(
        &mut self,
        text: &str,
        path: &str,
        short_first: bool,
        active: bool,
        report: &mut Report,
    ) -> (String, bool) {
        let mut ordinary = String::new();
        let mut present = false;
        for (offset, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if !candidate(raw) {
                ordinary.push_str(raw);
                ordinary.push('\n');
                continue;
            }
            self.present = true;
            present = true;
            self.declarations += 1;
            if !active {
                continue;
            }
            if self.declarations > MAX_DECLARATIONS {
                if self.declarations == MAX_DECLARATIONS + 1 {
                    report.issue("pattern_rewrites",Severity::Blocker,"Pattern rewrite import exceeds 512 rewrite declarations (including exceptions) across custom rules and bundled feeds; no extracted pattern rewrites were activated.");
                }
                self.invalid = true;
                continue;
            }
            let field = if short_first && offset == 0 {
                path.to_owned()
            } else {
                format!("{path}.lines[{offset}]")
            };
            if line.len() > MAX_LINE_BYTES {
                report.issue(
                    field,
                    Severity::Blocker,
                    "Pattern rewrite exceeds the 4096-byte rule limit.",
                );
                self.invalid = true;
                continue;
            }
            match parse(raw.trim_start(), field.clone()) {
                Ok(pattern) => self.patterns.push(pattern),
                Err(message) => {
                    report.issue(field, Severity::Blocker, message);
                    self.invalid = true;
                }
            }
        }
        (ordinary, present)
    }
}
fn below(name: &str, parent: &str) -> bool {
    name.strip_suffix(parent)
        .is_some_and(|prefix| prefix.ends_with('.'))
}
fn intersects(a: &str, descendants_a: bool, b: &str, descendants_b: bool) -> bool {
    a == b || (descendants_a && below(b, a)) || (descendants_b && below(a, b))
}
pub(super) fn translate(
    patterns: &[Pattern],
    filtering: &Value,
    prefix: &str,
    legacy: &[LocalRecord],
    separate_allowlist: bool,
    report: &mut Report,
) -> Vec<LocalRecord> {
    if patterns.is_empty() {
        return Vec::new();
    }
    if legacy.len() > 10_000 {
        report.issue(format!("{prefix}.rewrites"), Severity::Blocker, "Legacy local records exceed the 10000-record import budget; pattern overlap checks were not performed and no extracted pattern rewrites were activated.");
        return Vec::new();
    }
    let ttl = match filtering.get("blocked_response_ttl") {
        None => 10,
        Some(value) => match value.as_u64().filter(|ttl| *ttl <= 86400) {
            Some(ttl) => ttl as u32,
            None => {
                report.issue(format!("{prefix}.blocked_response_ttl"),Severity::Blocker,"Active pattern rewrites require an integer source TTL in 0..86400; no extracted pattern rewrites were activated.");
                return Vec::new();
            }
        },
    };
    if separate_allowlist {
        report.issue("whitelist_filters",Severity::Blocker,"Separate source allowlist engines can suppress pattern rewrites before ordinary rules; record conversion requires explicit priority review.");
        return Vec::new();
    }
    // Normalize legacy definitions once, off the executor, before bounded
    // overlap checks. Invalid native definitions still fail final validation.
    let owners: Vec<_> = legacy
        .iter()
        .filter_map(|record| {
            let (value, wildcard) = record
                .domain
                .strip_prefix("*.")
                .map_or((record.domain.as_str(), false), |suffix| (suffix, true));
            rustwalld_dns_filter::normalize(value)
                .ok()
                .map(|name| (name, wildcard))
        })
        .collect();
    let alias_targets: Vec<_> = legacy
        .iter()
        .filter_map(|record| match &record.data {
            LocalData::Cname { target } => rustwalld_dns_filter::normalize(target).ok(),
            _ => None,
        })
        .collect();
    // Resolve supported exceptions off the executor. Partial coverage needs
    // native effect-aware matching; an ordinary allow rule would be incorrect.
    let mut source_domains = std::collections::HashSet::new();
    let mut invalid = false;
    for pattern in patterns {
        source_domains.insert(pattern.domain.as_str());
        if source_domains.len() > MAX_PATTERNS {
            report.issue("pattern_rewrites",Severity::Blocker,"Pattern rewrite import exceeds 256 distinct owners; no extracted pattern rewrites were activated.");
            return Vec::new();
        }
        if pattern.exception
            && patterns
                .iter()
                .filter(|other| !other.exception)
                .any(|other| {
                    intersects(
                        &pattern.domain,
                        pattern.descendants,
                        &other.domain,
                        other.descendants,
                    ) && (pattern.domain != other.domain
                        || pattern.descendants != other.descendants)
                })
        {
            report.issue(&pattern.field,Severity::Blocker,"Rewrite exceptions require identical pattern coverage or disjoint names; partial intersections need native effect-aware matching. No extracted pattern rewrites were activated.");
            invalid = true;
        }
    }
    let retained: Vec<_> = patterns
        .iter()
        .filter(|pattern| !pattern.exception)
        .filter(|pattern| {
            !patterns.iter().any(|exception| {
                exception.exception
                    && exception.domain == pattern.domain
                    && exception.descendants == pattern.descendants
                    && (exception.response.is_none() || exception.response == pattern.response)
            })
        })
        .collect();
    let mut domains: HashMap<&str, (bool, Vec<&Response>)> = HashMap::new();
    for pattern in &retained {
        let Some(response) = pattern.response.as_ref() else {
            continue;
        };
        if response.alias_target().is_some_and(|target| {
            target == pattern.domain || (pattern.descendants && below(target, &pattern.domain))
        }) {
            report.issue(&pattern.field,Severity::Blocker,"HTTPS/SVCB AliasMode target cannot alias its own exact or synthesized wildcard owner; no extracted pattern rewrites were activated.");
            invalid = true;
        }
        if let Some((descendants, values)) = domains.get_mut(pattern.domain.as_str()) {
            if values.iter().any(|value| {
                value.kind() == response.kind()
                    && (response.alias_target().is_some() || value.alias_target().is_some())
            }) {
                report.issue(&pattern.field,Severity::Blocker,"HTTPS/SVCB AliasMode requires one record per owner/type; multiple aliases or mixed modes are unsupported. No extracted pattern rewrites were activated.");
                invalid = true;
            }
            let type_count = values
                .iter()
                .filter(|value| value.kind() == response.kind())
                .count();
            if *descendants != pattern.descendants
                || values.iter().any(|value| value.same_native_value(response))
                || type_count
                    >= if pattern.descendants && response.is_address() {
                        1
                    } else {
                        32
                    }
            {
                report.issue(&pattern.field,Severity::Blocker,"Duplicate native value, mixed exact/suffix owners or response count exceeds native limits (32 per type, one address per family for suffix); no extracted pattern rewrites were activated.");
                invalid = true;
            }
            values.push(response);
        } else {
            if domains.iter().any(|(owner, (descendants, _))| {
                intersects(&pattern.domain, pattern.descendants, owner, *descendants)
            }) {
                report.issue(&pattern.field,Severity::Blocker,"Overlapping pattern rewrites aggregate source answers, while native local records select an override; no extracted pattern rewrites were activated.");
                invalid = true;
            }
            domains.insert(&pattern.domain, (pattern.descendants, vec![response]));
        }
        if owners.iter().any(|(owner, wildcard)| {
            intersects(&pattern.domain, pattern.descendants, owner, *wildcard)
        }) || alias_targets.iter().any(|target| {
            target == &pattern.domain || (pattern.descendants && below(target, &pattern.domain))
        }) {
            report.issue(&pattern.field,Severity::Blocker,"Pattern coverage intersects a legacy rewrite owner or alias target; source priority requires review. No extracted pattern rewrites were activated.");
            invalid = true;
        }
    }
    if invalid {
        return Vec::new();
    }
    for exception in patterns.iter().filter(|pattern| pattern.exception) {
        report.issue(&exception.field,Severity::Info,"Same-pattern rewrite exception was resolved in the imported record set; it is not an ordinary allow rule and is not retained as a live exception. Review surviving records under Local DNS & routes.");
    }
    let mut records = Vec::with_capacity(retained.len() * 2);
    for pattern in retained {
        let Some(response) = pattern.response.as_ref() else {
            continue;
        };
        let data = response.local();
        records.push(LocalRecord {
            domain: pattern.domain.clone(),
            ttl,
            data: data.clone(),
        });
        if pattern.descendants {
            records.push(LocalRecord {
                domain: format!("*.{}", pattern.domain),
                ttl,
                data,
            });
        }
        report.translated_rules += 1;
        report.issue(&pattern.field,Severity::Info,if response.is_address() {
            "Literal address pattern rewrite became native local DNS records, retaining source TTL. Suffix conversion includes the apex and descendants; future edits use Local DNS & routes, not the original source rule text."
        } else if pattern.descendants {
            "Literal typed pattern rewrite became apex and descendant native local DNS records, retaining source TTL. Edit both under Local DNS & routes; source exceptions are resolved once during import."
        } else {
            "Literal typed pattern rewrite became exact native local DNS records, retaining source TTL. Future edits use Local DNS & routes; source exceptions are resolved once during import."
        });
    }
    records
}
