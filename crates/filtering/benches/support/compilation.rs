//! Shared deterministic compilation fixtures; generation is never timed.
use rustwalld_dns_filter::{Action, ListInput};
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
            "idna" => writeln!(rules, "=bücher{i}.bench")?,
            _ => return Err("workload must be mixed, suffix or idna".into()),
        }
    }
    Ok(vec![ListInput {
        name: "fixture".into(),
        action: Action::Block,
        rules,
    }])
}
