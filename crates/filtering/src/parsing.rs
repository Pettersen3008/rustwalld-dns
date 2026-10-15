//! Control-plane normalization and native/AdGuard input interpretation.
use crate::{Action, CompileError, Matcher, RuleSyntax, compile, exclusions, regex_rules};

/// Control-plane normalization. Query names are already ASCII DNS labels.
///
/// Converts to lowercase IDNA ASCII without the root dot.
///
/// # Errors
///
/// [`CompileError::Domain`] for names that are empty, too long, or contain
/// invalid labels.
pub fn normalize(input: &str) -> Result<String, CompileError> {
    let input = input.strip_suffix('.').unwrap_or(input);
    let ascii = idna::domain_to_ascii(input)
        .map_err(|_| CompileError::Domain(input.to_owned()))?
        .to_ascii_lowercase();
    if ascii.is_empty()
        || ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
    {
        return Err(CompileError::Domain(input.to_owned()));
    }
    Ok(ascii)
}
pub(super) fn parse_rule(line: &str, default: Action, syntax: RuleSyntax) -> compile::ParsedRules {
    if matches!(
        syntax,
        RuleSyntax::Adguard
            | RuleSyntax::AdguardV2
            | RuleSyntax::AdguardV3
            | RuleSyntax::AdguardV4
            | RuleSyntax::AdguardV5
            | RuleSyntax::AdguardV6
    ) {
        return adguard_rule(line, default);
    }
    let regex_line = line.strip_prefix("@@").unwrap_or(line);
    if let Some(pattern) = regex_line
        .strip_prefix('/')
        .and_then(|line| line.strip_suffix('/'))
    {
        regex_rules::validate(pattern)?;
        let action = if line.starts_with("@@") {
            Action::Allow
        } else {
            default
        };
        return Ok(vec![exclusions::ParsedRule::plain(
            action,
            Matcher::Regex,
            pattern.to_owned(),
        )]);
    }
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() > 1 {
        if !matches!(fields[0], "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
            return Err(CompileError::Domain(line.to_owned()));
        }
        return fields[1..]
            .iter()
            .map(|domain| {
                Ok(exclusions::ParsedRule::plain(
                    default,
                    Matcher::Suffix,
                    normalize(domain)?,
                ))
            })
            .collect();
    }
    let (action, line) = if let Some(line) = line.strip_prefix("@@") {
        (Action::Allow, line)
    } else {
        (default, line)
    };
    let (matcher, domain) = if let Some(domain) = line.strip_prefix('=') {
        (Matcher::Exact, domain)
    } else if let Some(domain) = line.strip_prefix("||").and_then(|s| s.strip_suffix('^')) {
        (Matcher::Suffix, domain)
    } else if let Some(domain) = line.strip_prefix("*.") {
        (Matcher::Suffix, domain)
    } else {
        (Matcher::Suffix, line)
    };
    Ok(vec![exclusions::ParsedRule::plain(
        action,
        matcher,
        normalize(domain)?,
    )])
}
fn adguard_rule(line: &str, default: Action) -> compile::ParsedRules {
    let (action, pattern) = line
        .strip_prefix("@@")
        .map_or((default, line), |pattern| (Action::Allow, pattern));
    if let Some(regex) = pattern
        .strip_prefix('/')
        .and_then(|value| value.strip_suffix('/'))
    {
        regex_rules::validate(regex)?;
        return Ok(vec![exclusions::ParsedRule::plain(
            action,
            Matcher::Regex,
            regex.into(),
        )]);
    }
    let fields: Vec<_> = pattern.split_whitespace().collect();
    if fields.len() > 1 {
        let ip = fields[0]
            .parse::<std::net::IpAddr>()
            .map_err(|_| CompileError::Domain("unsupported hosts rule".into()))?;
        if !ip.is_unspecified() && !ip.is_loopback() {
            return Err(CompileError::Domain(
                "hosts address requires a local DNS record".into(),
            ));
        }
        return fields[1..]
            .iter()
            .map(|domain| {
                Ok(exclusions::ParsedRule::plain(
                    action,
                    Matcher::Exact,
                    normalize(domain)?,
                ))
            })
            .collect();
    }
    if pattern.contains('$') {
        return Err(CompileError::Domain("unsupported rule modifier".into()));
    }
    if let Ok(domain) = normalize(pattern) {
        return Ok(vec![exclusions::ParsedRule::plain(
            action,
            Matcher::Exact,
            domain,
        )]);
    }
    if let Some(domain) = pattern
        .strip_prefix("||")
        .and_then(|value| value.strip_suffix('^'))
        && let Ok(domain) = normalize(domain)
    {
        return Ok(vec![exclusions::ParsedRule::plain(
            action,
            Matcher::Suffix,
            domain,
        )]);
    }
    if let Some(domain) = pattern
        .strip_prefix('|')
        .and_then(|value| value.strip_suffix('^').or_else(|| value.strip_suffix('|')))
        && let Ok(domain) = normalize(domain)
    {
        return Ok(vec![exclusions::ParsedRule::plain(
            action,
            Matcher::Exact,
            domain,
        )]);
    }
    if pattern.len() > 4096 || !pattern.is_ascii() || pattern.contains('/') {
        return Err(CompileError::Domain("invalid hostname mask".into()));
    }
    let (start, body) = if let Some(body) = pattern.strip_prefix("||") {
        ("(?:^|\\.)", body)
    } else if let Some(body) = pattern.strip_prefix('|') {
        ("^", body)
    } else {
        ("", pattern)
    };
    let (body, end) = body
        .strip_suffix('^')
        .or_else(|| body.strip_suffix('|'))
        .map_or((body, ""), |body| (body, "$"));
    if body.is_empty() || body.contains(['|', '^']) {
        return Err(CompileError::Domain("invalid hostname mask".into()));
    }
    let regex = format!(
        "{start}{}{end}",
        body.split('*')
            .map(regex::escape)
            .collect::<Vec<_>>()
            .join(".*")
    );
    regex_rules::validate(&regex)?;
    Ok(vec![exclusions::ParsedRule::plain(
        action,
        Matcher::Regex,
        regex,
    )])
}
