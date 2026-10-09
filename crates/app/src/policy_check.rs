//! Offline file loading and diagnostic presentation, outside the DNS executor.
use crate::config::Config;
use clap::ValueEnum;
use rustwalld_dns_filter::Action;
use rustwalld_dns_policy::{AssertionFailure, CheckReport, PolicySnapshot};
use std::{error::Error, io::Write, path::Path};

#[derive(Clone, Copy, Default, ValueEnum)]
pub enum Format {
    #[default]
    Text,
    Json,
}

pub fn run(path: &Path, format: Format) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let config = Config::read(path)?;
    let report = PolicySnapshot::check(config.policy)?;
    let mut stdout = std::io::stdout().lock();
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut stdout, &report)?;
            writeln!(stdout)?;
        }
        Format::Text => write_text(&mut stdout, &report)?,
    }
    Ok(report.valid)
}

fn action(action: Action) -> &'static str {
    match action {
        Action::Allow => "ALLOW",
        Action::Block => "BLOCK",
    }
}

fn write_text(output: &mut impl Write, report: &CheckReport) -> std::io::Result<()> {
    writeln!(
        output,
        "Basis: permanent policy (temporary exceptions excluded)"
    )?;
    writeln!(
        output,
        "Policy assertions: {}/{} passed ({} policies)",
        report.assertions - report.failed,
        report.assertions,
        report.policies
    )?;
    if report.assertions == 0 {
        writeln!(
            output,
            "No required assertions configured; only structural validation was performed."
        )?;
    }
    for (index, result) in report.results.iter().enumerate() {
        writeln!(
            output,
            "{} [{}] {} + {:?}: expected {}",
            if result.failure.is_none() {
                "PASS"
            } else {
                "FAIL"
            },
            index + 1,
            result.assertion.client,
            result.assertion.domain,
            action(result.assertion.expected)
        )?;
        if let Some(failure) = &result.failure {
            writeln!(
                output,
                "  Reason: {}",
                match failure {
                    AssertionFailure::ClientNotPermitted =>
                        "client is outside allowed networks; trace is hypothetical",
                    AssertionFailure::InvalidDomain => "invalid domain",
                    AssertionFailure::UnexpectedDecision => "decision differs from the assertion",
                    _ => "assertion failed",
                }
            )?;
        }
        writeln!(output, "  Client admitted: {}", result.permitted)?;
        if let Some(trace) = &result.trace {
            writeln!(
                output,
                "  Domain: {:?}; policy: {:?}; decision: {}{}",
                trace.domain,
                trace.policy,
                action(trace.decision.action),
                if trace.rewrite {
                    " (local rewrite)"
                } else {
                    ""
                },
            )?;
            writeln!(
                output,
                "  Client name: {:?}; network: {:?}; upstream profile: {:?}",
                trace.client_name, trace.network, trace.upstream
            )?;
            if let Some(metadata) = &trace.binding_metadata {
                writeln!(
                    output,
                    "  Group: {:?}; owner: {:?}; VLAN label: {:?}; tags: {:?}; note: {:?}",
                    metadata.group, metadata.owner, metadata.vlan, metadata.tags, metadata.note
                )?;
            }
            if let Some(rule) = &trace.rule {
                writeln!(
                    output,
                    "  Matcher: {:?}; rule: {:?}",
                    rule.matcher, rule.domain
                )?;
                for source in &rule.sources {
                    writeln!(output, "  Source: {:?}, line {}", source.list, source.line)?;
                }
                if rule.total_sources > rule.sources.len() {
                    writeln!(
                        output,
                        "  Sources shown: {} of {}",
                        rule.sources.len(),
                        rule.total_sources
                    )?;
                }
            } else if !trace.rewrite {
                writeln!(output, "  Matcher: none (default allow)")?;
            }
        }
    }
    Ok(())
}
