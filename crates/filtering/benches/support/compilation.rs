//! Shared deterministic compilation fixtures; generation is never timed.
use rustwalld_dns_filter::{Action, ListInput, RuleSyntax};
use std::{error::Error, fmt::Write};
pub fn fixture(size: usize, workload: &str) -> Result<Vec<ListInput>, Box<dyn Error>> {
    if !(100..=10_000_000).contains(&size) {
        return Err("size must be between 100 and 10000000".into());
    }
    let mut rules = String::new();
    for i in 0..size {
        match workload {
            "mixed" if i.is_multiple_of(2) => writeln!(rules, "=exact{i}.bench")?,
            "mixed" => writeln!(rules, "suffix{i}.bench")?,
            "suffix" => writeln!(rules, "rule{i}.compile.test")?,
            "tags" if i < 512 => writeln!(
                rules,
                "||active{i}.compile.test^$ctag=device_phone|~user_admin,dnstype=A|AAAA"
            )?,
            "client" if i < 512 => writeln!(
                rules,
                "||active{i}.compile.test^$client=192.0.2.0/24|Kids{i},dnstype=A|AAAA"
            )?,
            "dnstype" if i < 512 => writeln!(
                rules,
                "||active{i}.compile.test^$dnstype=A|AAAA,denyallow=safe{i}.active{i}.compile.test"
            )?,
            "denyallow" if i < 512 => writeln!(
                rules,
                "||active{i}.compile.test^$denyallow=safe{i}.active{i}.compile.test"
            )?,
            "adguard" | "badfilter" | "denyallow" | "dnstype" | "client" | "tags" => {
                writeln!(rules, "||active{i}.compile.test^")?
            }
            "idna" => writeln!(rules, "=bücher{i}.bench")?,
            _ => {
                return Err(
                    "workload must be mixed, suffix, idna, adguard, badfilter, denyallow, dnstype, client or tags".into(),
                );
            }
        }
    }
    if workload == "badfilter" {
        for i in 0..(size / 100).min(65_536) {
            writeln!(rules, "||disabled{i}.compile.test^")?;
            writeln!(rules, "||disabled{i}.compile.test^$badfilter")?;
        }
    }
    Ok(vec![ListInput {
        syntax: if workload == "tags" {
            RuleSyntax::AdguardV6
        } else if workload == "client" {
            RuleSyntax::AdguardV5
        } else if workload == "dnstype" {
            RuleSyntax::AdguardV4
        } else if workload == "denyallow" {
            RuleSyntax::AdguardV3
        } else if matches!(workload, "adguard" | "badfilter") {
            RuleSyntax::AdguardV2
        } else {
            RuleSyntax::Native
        },
        name: "fixture".into(),
        action: Action::Block,
        rules,
    }])
}
