//! Sample only child-owned sockets whose remote ports match local fixtures.
use serde_json::{Value, json};
use std::{collections::HashSet, path::PathBuf};
pub fn sample(pid: u32, ports: &HashSet<u16>) -> Value {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let entries = std::fs::read_dir(root.join("fd"))
        .unwrap()
        .collect::<Vec<_>>();
    let inodes: HashSet<String> = entries
        .iter()
        .filter_map(|e| std::fs::read_link(e.as_ref().ok()?.path()).ok())
        .filter_map(|p| {
            p.to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')
                .map(str::to_owned)
        })
        .collect();
    let mut sockets = 0;
    for table in ["net/tcp", "net/tcp6"] {
        for line in std::fs::read_to_string(root.join(table))
            .unwrap()
            .lines()
            .skip(1)
        {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() > 9
                && inodes.contains(fields[9])
                && fields[2]
                    .rsplit(':')
                    .next()
                    .and_then(|p| u16::from_str_radix(p, 16).ok())
                    .is_some_and(|p| ports.contains(&p))
            {
                sockets += 1;
            }
        }
    }
    let status = std::fs::read_to_string(root.join("status")).unwrap();
    let value = |key: &str| {
        status
            .lines()
            .find_map(|line| {
                line.strip_prefix(key)?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .unwrap()
    };
    json!({"upstream_sockets":sockets,"fds":entries.len(),"native_threads":value("Threads:"),"rss_kib":value("VmRSS:")})
}
