//! Offline client grammar and bounded immutable cache-equivalence classes.
use crate::{CompileError, Rule};
use ipnet::IpNet;
use std::{collections::BTreeSet, net::IpAddr, sync::Arc};
/// Client identity from an explicit binding in the pinned policy generation.
#[derive(Clone, Copy, Debug)]
pub struct ClientContext<'a> {
    /// Actual source address; mapped addresses are canonicalized when matching.
    pub ip: IpAddr,
    /// Exact configured binding name, never a discovered inventory label.
    pub name: Option<&'a str>,
}
/// One immutable network or case-sensitive name restriction.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(untagged)]
pub enum ClientValue {
    /// Canonical IP prefix; an individual IP uses its full-width prefix.
    Network(IpNet),
    /// Exact persistent-client name.
    Name(Arc<str>),
}
/// Exclusions win; nonempty inclusions narrow applicability to matching clients.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct ClientSelector {
    /// Sorted included client identities.
    include: Box<[ClientValue]>,
    /// Sorted excluded client identities.
    exclude: Box<[ClientValue]>,
    #[serde(skip)]
    networks: Option<Box<NetworkSets>>,
}
impl ClientSelector {
    /// Read-only normalized identities included by this compiled selector.
    pub fn include(&self) -> &[ClientValue] {
        &self.include
    }
    /// Read-only normalized identities excluded by this compiled selector.
    pub fn exclude(&self) -> &[ClientValue] {
        &self.exclude
    }
    /// Match an actual source address and explicit configured name.
    pub fn matches(&self, client: ClientContext<'_>) -> bool {
        fn named(values: &[ClientValue], name: Option<&str>) -> bool {
            name.is_some_and(|name| {
                values
                    .binary_search_by(|value| match value {
                        ClientValue::Name(value) => value.as_ref().cmp(name),
                        ClientValue::Network(_) => std::cmp::Ordering::Less,
                    })
                    .is_ok()
            })
        }
        let (included, excluded) = self.networks.as_ref().map_or((false, false), |networks| {
            networks.matches(client.ip.to_canonical())
        });
        !excluded
            && !named(&self.exclude, client.name)
            && (self.include.is_empty() || included || named(&self.include, client.name))
    }
    pub(super) fn count(&self) -> usize {
        self.include.len() + self.exclude.len()
    }
    pub(super) fn payload_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .networks
                .as_ref()
                .map_or(0, |networks| networks.payload_bytes())
            + self.count() * std::mem::size_of::<ClientValue>()
            + self
                .include
                .iter()
                .chain(self.exclude.iter())
                .map(|value| match value {
                    ClientValue::Name(name) => name.len(),
                    _ => 0,
                })
                .sum::<usize>()
    }
    pub(super) fn parse(text: &str) -> Result<Self, CompileError> {
        let values = split_escaped(text, '|');
        if values.is_empty() || values.len() > 64 {
            return Err(CompileError::Domain(
                "invalid or oversized client modifier".into(),
            ));
        }
        let (mut include, mut exclude) = (Vec::new(), Vec::new());
        for value in values {
            let (restricted, value) = value
                .strip_prefix('~')
                .map_or((false, value.as_str()), |value| (true, value));
            let quote = value.as_bytes().first().copied().filter(|q| {
                matches!(q, b'\'' | b'"') && value.len() >= 2 && value.as_bytes().last() == Some(q)
            });
            let value = if let Some(quote) = quote {
                value[1..value.len() - 1].replace(
                    &format!("\\{}", char::from(quote)),
                    &char::from(quote).to_string(),
                )
            } else {
                value.to_owned()
            };
            let value = value.replace("\\,", ",");
            if value.trim().is_empty() || value.len()>128 || value.chars().any(|c|c.is_control() || matches!(c,'\u{061c}'|'\u{200e}'|'\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')) {return Err(CompileError::Domain("invalid client identity".into()));}
            let value = if let Ok(address) = value.parse::<IpAddr>() {
                ClientValue::Network(IpNet::from(address))
            } else if let Ok(network) = value.parse::<IpNet>() {
                ClientValue::Network(network.trunc())
            } else {
                ClientValue::Name(value.into())
            };
            if restricted {
                exclude.push(value);
            } else {
                include.push(value);
            }
        }
        include.sort_unstable();
        include.dedup();
        exclude.sort_unstable();
        exclude.dedup();
        let networks = NetworkSets::compile(&include, &exclude);
        Ok(Self {
            networks,
            include: include.into_boxed_slice(),
            exclude: exclude.into_boxed_slice(),
        })
    }
}
/// Source-equivalent escaped separator handling, with empty entries retained for
/// strict validation rather than silently ignoring malformed source tokens.
pub(super) fn split_escaped(text: &str, separator: char) -> Vec<String> {
    let mut values = Vec::new();
    let mut value = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&separator) {
            value.push(separator);
            chars.next();
        } else if c == separator {
            values.push(std::mem::take(&mut value));
        } else {
            value.push(c);
        }
    }
    values.push(value);
    values
}
/// Sorted interval endpoints partition addresses so every predicate is constant
/// within a cell. Name IDs partition exact identities, including an unknown class.
#[derive(Debug)]
pub(super) struct ClientClasses {
    v4: Box<[u128]>,
    v6: Box<[u128]>,
    names: hashbrown::HashMap<Arc<str>, u32, foldhash::fast::RandomState>,
}
impl ClientClasses {
    pub(super) fn compile(rules: &[Rule]) -> Result<Option<Box<Self>>, CompileError> {
        let (mut v4, mut v6, mut names) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        let mut found = false;
        for selector in rules.iter().filter_map(Rule::client) {
            found = true;
            for value in selector.include.iter().chain(selector.exclude.iter()) {
                match value {
                    ClientValue::Name(name) => {
                        names.insert(name.clone());
                    }
                    ClientValue::Network(network) => {
                        let (start, end, bounds) = match network {
                            IpNet::V4(network) => (
                                u128::from(u32::from(network.network())),
                                u128::from(u32::from(network.broadcast())),
                                &mut v4,
                            ),
                            IpNet::V6(network) => (
                                u128::from(network.network()),
                                u128::from(network.broadcast()),
                                &mut v6,
                            ),
                        };
                        bounds.insert(start);
                        if let Some(after) = end.checked_add(1) {
                            bounds.insert(after);
                        }
                    }
                }
            }
        }
        // 8192 identities imply at most16386 address cells and8192 name IDs.
        if v4.len() + v6.len() > 16384 || names.len() > 8192 {
            return Err(CompileError::Limit);
        }
        let names = names
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                u32::try_from(index + 1)
                    .map(|index| (name, index))
                    .map_err(|_| CompileError::Limit)
            })
            .collect::<Result<_, _>>()?;
        Ok(found.then(|| {
            Box::new(Self {
                v4: v4.into_iter().collect(),
                v6: v6.into_iter().collect(),
                names,
            })
        }))
    }
    pub(super) fn partition(&self, client: ClientContext<'_>) -> u32 {
        let ip = if self.v4.is_empty() && self.v6.is_empty() {
            0
        } else {
            match client.ip.to_canonical() {
                IpAddr::V4(ip) => {
                    1 + self
                        .v4
                        .partition_point(|cut| *cut <= u128::from(u32::from(ip)))
                }
                IpAddr::V6(ip) => {
                    2 + self.v4.len() + self.v6.partition_point(|cut| *cut <= u128::from(ip))
                }
            }
        };
        // Construction proves both bounded indices fit without truncation.
        ((ip as u32) << 14)
            | client
                .name
                .and_then(|name| self.names.get(name))
                .copied()
                .unwrap_or(0)
    }
    pub(super) fn payload_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + (self.v4.len() + self.v6.len()) * std::mem::size_of::<u128>()
            + self.names.len() * std::mem::size_of::<(Arc<str>, u32)>()
            + self.names.keys().map(|name| name.len()).sum::<usize>()
    }
}

/// Sorted disjoint ranges; prefix merging happens only during compilation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Range {
    start: u128,
    end: u128,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct NetworkSets {
    include_v4: Box<[Range]>,
    include_v6: Box<[Range]>,
    exclude_v4: Box<[Range]>,
    exclude_v6: Box<[Range]>,
}
impl NetworkSets {
    fn compile(include: &[ClientValue], exclude: &[ClientValue]) -> Option<Box<Self>> {
        fn ranges(values: &[ClientValue], v4: bool) -> Box<[Range]> {
            let mut ranges = values
                .iter()
                .filter_map(|value| match value {
                    ClientValue::Network(IpNet::V4(network)) if v4 => Some(Range {
                        start: u128::from(u32::from(network.network())),
                        end: u128::from(u32::from(network.broadcast())),
                    }),
                    ClientValue::Network(IpNet::V6(network)) if !v4 => Some(Range {
                        start: u128::from(network.network()),
                        end: u128::from(network.broadcast()),
                    }),
                    _ => None,
                })
                .collect::<Vec<_>>();
            ranges.sort_unstable_by_key(|range| range.start);
            let mut merged: Vec<Range> = Vec::new();
            for range in ranges {
                if let Some(last) = merged.last_mut()
                    && range.start <= last.end.saturating_add(1)
                {
                    last.end = last.end.max(range.end);
                } else {
                    merged.push(range);
                }
            }
            merged.into_boxed_slice()
        }
        if !include
            .iter()
            .chain(exclude)
            .any(|value| matches!(value, ClientValue::Network(_)))
        {
            return None;
        }
        Some(Box::new(Self {
            include_v4: ranges(include, true),
            include_v6: ranges(include, false),
            exclude_v4: ranges(exclude, true),
            exclude_v6: ranges(exclude, false),
        }))
    }
    fn matches(&self, ip: IpAddr) -> (bool, bool) {
        fn contains(ranges: &[Range], address: u128) -> bool {
            let index = ranges.partition_point(|range| range.start <= address);
            index
                .checked_sub(1)
                .and_then(|index| ranges.get(index))
                .is_some_and(|range| address <= range.end)
        }
        match ip {
            IpAddr::V4(ip) => {
                let ip = u128::from(u32::from(ip));
                (
                    contains(&self.include_v4, ip),
                    contains(&self.exclude_v4, ip),
                )
            }
            IpAddr::V6(ip) => {
                let ip = u128::from(ip);
                (
                    contains(&self.include_v6, ip),
                    contains(&self.exclude_v6, ip),
                )
            }
        }
    }
    fn payload_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + (self.include_v4.len()
                + self.include_v6.len()
                + self.exclude_v4.len()
                + self.exclude_v6.len())
                * std::mem::size_of::<Range>()
    }
}
