//! Compiled exact-domain allows. Expiry never depends on a management task.
use crate::{
    CompiledPolicy, PolicyConfigSet, PolicyError,
    config::{excerpt, validate_name},
    sources::MAX_UNIX_SECONDS,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Longest time a newly accepted temporary exception may last.
pub const MAX_EXCEPTION_REMAINING: Duration = Duration::from_secs(7 * 86400);

/// An operator-approved, time-limited exact-domain allow.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporaryException {
    /// Unique label within its policy.
    pub name: String,
    /// Domain allowed exactly (not its subdomains).
    pub domain: String,
    /// Absolute expiry, in Unix seconds.
    pub expires_at: u64,
    /// Source networks; empty applies to every admitted client of this policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<IpNet>,
    /// Include subdomains. `*` pauses filtering for the selected clients.
    #[serde(default, skip_serializing_if = "is_false")]
    pub include_subdomains: bool,
}
fn is_false(value: &bool) -> bool {
    !value
}

pub(crate) struct Clock {
    monotonic: Instant,
    wall: SystemTime,
}
impl Clock {
    pub(crate) fn now() -> Self {
        // Wall is captured after monotonic, making the derived deadline conservative.
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}
struct Entry {
    index: u16,
    exception: TemporaryException,
    wall: SystemTime,
    deadline: Instant,
    // A clock jump or suspend can expire an entry before the monotonic deadline.
    // Once observed expired it cannot revive if the clock subsequently moves back.
    expired: AtomicBool,
}
pub(crate) struct Entries(HashMap<String, Vec<Entry>>, bool);

/// A temporary exception in force for a query.
pub struct TemporaryMatch<'a> {
    /// Index within the policy's `temporary_exceptions`.
    pub index: u16,
    /// The configured exception.
    pub exception: &'a TemporaryException,
    entry: &'a Entry,
}
impl TemporaryMatch<'_> {
    /// Seconds of validity left at `now` by both the monotonic and wall
    /// clocks, or `None` once expired. Answers' TTLs are capped by this.
    pub fn remaining_ttl(&self, now: Instant) -> Option<u32> {
        self.entry.remaining_at(now, SystemTime::now())
    }
}
impl Entry {
    fn remaining_at(&self, now: Instant, wall: SystemTime) -> Option<u32> {
        if self.expired.load(Ordering::Relaxed) {
            return None;
        }
        let remaining = self
            .deadline
            .checked_duration_since(now)
            .zip(self.wall.duration_since(wall).ok())
            .filter(|(monotonic, wall)| !monotonic.is_zero() && !wall.is_zero());
        if let Some((monotonic, wall)) = remaining {
            Some(u32::try_from(monotonic.min(wall).as_secs()).unwrap_or(u32::MAX))
        } else {
            self.expired.store(true, Ordering::Relaxed);
            None
        }
    }
}
impl Entries {
    pub(crate) fn compile(
        policy: usize,
        inputs: &[TemporaryException],
        clock: &Clock,
    ) -> Result<Option<Self>, PolicyError> {
        let mut names = HashSet::new();
        let mut domains = HashSet::new();
        let mut entries = HashMap::new();
        for (index, input) in inputs.iter().enumerate() {
            let field =
                |name: &str| format!("policies[{policy}].temporary_exceptions[{index}].{name}");
            validate_name(&input.name, || field("name"))?;
            let domain = if input.domain == "*" {
                "*".into()
            } else {
                rustwalld_dns_filter::normalize(&input.domain)
                    .map_err(|_| PolicyError::field(field("domain"), excerpt(&input.domain)))?
            };
            if input.clients.len() > 64 {
                return Err(PolicyError::field(
                    field("clients"),
                    "at most 64 client networks per exception",
                ));
            }
            let mut clients = input
                .clients
                .iter()
                .map(|network| {
                    crate::compile::canonical_network(*network, || field("clients"))
                        .map(|net| net.trunc())
                })
                .collect::<Result<Vec<_>, _>>()?;
            clients.sort_unstable();
            clients.dedup();
            if !names.insert(&input.name) {
                return Err(PolicyError::field(
                    field("name"),
                    format!("duplicate exception name {}", excerpt(&input.name)),
                ));
            }
            if !domains.insert((domain.clone(), input.include_subdomains, clients.clone())) {
                return Err(PolicyError::field(
                    field("domain"),
                    format!("duplicate exception domain {domain}"),
                ));
            }
            if !(1..=MAX_UNIX_SECONDS).contains(&input.expires_at) {
                return Err(PolicyError::field(
                    field("expires_at"),
                    format!(
                        "{} is outside 1 through {MAX_UNIX_SECONDS}",
                        input.expires_at
                    ),
                ));
            }
            let wall = UNIX_EPOCH
                .checked_add(Duration::from_secs(input.expires_at))
                .ok_or_else(|| PolicyError::field(field("expires_at"), "unrepresentable time"))?;
            let Ok(remaining) = wall.duration_since(clock.wall) else {
                continue;
            };
            if remaining.is_zero() {
                continue;
            }
            // Stored revisions are recompiled at startup with whatever the wall
            // clock says. A clock that is behind (an RTC-less board before NTP)
            // must not keep DNS from starting, so bound only the monotonic
            // deadline here. The absolute wall expiry still ends the allowance
            // once the clock is corrected; intake enforces the seven-day limit.
            let remaining = remaining.min(MAX_EXCEPTION_REMAINING);
            let deadline = clock.monotonic.checked_add(remaining).ok_or_else(|| {
                PolicyError::field(field("expires_at"), "unrepresentable deadline")
            })?;
            let index = u16::try_from(index).map_err(|_| PolicyError::Count {
                field: format!("policies[{policy}].temporary_exceptions"),
                actual: inputs.len(),
                min: 0,
                max: usize::from(u16::MAX),
            })?;
            let mut exception = input.clone();
            exception.domain.clone_from(&domain);
            exception.clients = clients;
            entries.entry(domain).or_insert_with(Vec::new).push(Entry {
                index,
                exception,
                wall,
                deadline,
                expired: AtomicBool::new(false),
            });
        }
        Ok((!entries.is_empty()).then_some(Self(
            entries,
            inputs.iter().any(|input| input.include_subdomains),
        )))
    }
}
impl PolicyConfigSet {
    /// Intake check for newly accepted temporary exceptions.
    ///
    /// An exception is new unless an identical entry (policy name, exception
    /// name, domain and expiry) exists in one of the `accepted` configurations,
    /// such as the live active and shadow revisions. New exceptions may have at
    /// most [`MAX_EXCEPTION_REMAINING`] left on the current wall clock; expired
    /// ones are inert and accepted. Compilation itself never applies this limit:
    /// it clamps the monotonic deadline so that restoring a stored revision
    /// with a lagging clock still starts DNS.
    pub fn validate_new_exceptions(
        &self,
        accepted: &[&PolicyConfigSet],
    ) -> Result<(), PolicyError> {
        self.validate_new_exceptions_at(accepted, SystemTime::now())
    }
    pub(crate) fn validate_new_exceptions_at(
        &self,
        accepted: &[&PolicyConfigSet],
        now: SystemTime,
    ) -> Result<(), PolicyError> {
        let known: HashSet<_> = accepted
            .iter()
            .flat_map(|config| &config.policies)
            .flat_map(|policy| {
                policy.temporary_exceptions.iter().map(move |exception| {
                    (
                        policy.name.as_str(),
                        exception.name.as_str(),
                        exception.domain.as_str(),
                        exception.expires_at,
                        exception.clients.as_slice(),
                        exception.include_subdomains,
                    )
                })
            })
            .collect();
        for (policy_index, policy) in self.policies.iter().enumerate() {
            for (index, exception) in policy.temporary_exceptions.iter().enumerate() {
                let key = (
                    policy.name.as_str(),
                    exception.name.as_str(),
                    exception.domain.as_str(),
                    exception.expires_at,
                    exception.clients.as_slice(),
                    exception.include_subdomains,
                );
                // Unrepresentable expiries are reported by compilation.
                let remaining = UNIX_EPOCH
                    .checked_add(Duration::from_secs(exception.expires_at))
                    .and_then(|expiry| expiry.duration_since(now).ok());
                if remaining.is_some_and(|remaining| remaining > MAX_EXCEPTION_REMAINING)
                    && !known.contains(&key)
                {
                    return Err(PolicyError::field(
                        format!(
                            "policies[{policy_index}].temporary_exceptions[{index}].expires_at"
                        ),
                        format!(
                            "exception {} has more than seven days remaining",
                            excerpt(&exception.name)
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}
impl CompiledPolicy {
    /// Name is normalized ASCII without a root dot. No allocation or global lock.
    pub fn temporary_allow(&self, domain: &str, now: Instant) -> Option<TemporaryMatch<'_>> {
        self.temporary_match(domain, None, now)
    }
    /// Lookup for the actual source IP. Does not change client admission.
    pub fn temporary_allow_for(
        &self,
        domain: &str,
        client: IpAddr,
        now: Instant,
    ) -> Option<TemporaryMatch<'_>> {
        self.temporary_match(domain, Some(client.to_canonical()), now)
    }
    /// Expiry status for management; independent of a client/name match.
    pub fn temporary_exception_active(&self, index: usize, now: Instant) -> bool {
        self.exceptions.as_ref().is_some_and(|entries| {
            entries.0.values().flatten().any(|entry| {
                usize::from(entry.index) == index
                    && entry.remaining_at(now, SystemTime::now()).is_some()
            })
        })
    }
    fn temporary_match(
        &self,
        domain: &str,
        client: Option<IpAddr>,
        now: Instant,
    ) -> Option<TemporaryMatch<'_>> {
        let entries = &self.exceptions.as_ref()?.0;
        let mut suffix = domain;
        loop {
            if let Some(matches) = entries.get(suffix) {
                for entry in matches {
                    if suffix != domain && !entry.exception.include_subdomains {
                        continue;
                    }
                    if !entry.exception.clients.is_empty()
                        && !client.is_some_and(|ip| {
                            entry.exception.clients.iter().any(|net| net.contains(&ip))
                        })
                    {
                        continue;
                    }
                    let found = TemporaryMatch {
                        index: entry.index,
                        exception: &entry.exception,
                        entry,
                    };
                    if found.remaining_ttl(now).is_some() {
                        return Some(found);
                    }
                }
            }
            if !self.exceptions.as_ref()?.1 {
                break;
            }
            match suffix.find('.') {
                Some(dot) => suffix = &suffix[dot + 1..],
                None => break,
            }
        }
        entries.get("*")?.iter().find_map(|entry| {
            if !entry.exception.clients.is_empty()
                && !client
                    .is_some_and(|ip| entry.exception.clients.iter().any(|net| net.contains(&ip)))
            {
                return None;
            }
            let found = TemporaryMatch {
                index: entry.index,
                exception: &entry.exception,
                entry,
            };
            found.remaining_ttl(now).map(|_| found)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn scoped_exact_suffix_and_pause_never_grant_other_clients_or_admission() {
        let mut config = PolicyConfigSet::default();
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        config.policies[0].temporary_exceptions = vec![
            TemporaryException {
                name: "exact".into(),
                domain: "ads.test".into(),
                expires_at: expiry,
                clients: vec!["::ffff:127.0.0.1/128".parse().unwrap()],
                include_subdomains: false,
            },
            TemporaryException {
                name: "suffix".into(),
                domain: "ads.test".into(),
                expires_at: expiry,
                clients: vec!["127.0.0.2/32".parse().unwrap()],
                include_subdomains: true,
            },
            TemporaryException {
                name: "pause".into(),
                domain: "*".into(),
                expires_at: expiry,
                clients: vec!["127.0.0.3/32".parse().unwrap()],
                include_subdomains: false,
            },
        ];
        let snapshot = crate::PolicySnapshot::compile(config.clone(), 1).unwrap();
        let policy = &snapshot.policies()[0];
        let now = Instant::now();
        assert!(policy.temporary_allow("ads.test", now).is_none());
        assert!(
            policy
                .temporary_allow_for("ads.test", "127.0.0.1".parse().unwrap(), now)
                .is_some()
        );
        assert!(
            policy
                .temporary_allow_for("sub.ads.test", "127.0.0.1".parse().unwrap(), now)
                .is_none()
        );
        assert!(
            policy
                .temporary_allow_for("sub.ads.test", "127.0.0.2".parse().unwrap(), now)
                .is_some()
        );
        assert!(
            policy
                .temporary_allow_for("badads.test", "127.0.0.2".parse().unwrap(), now)
                .is_none()
        );
        assert!(
            policy
                .temporary_allow_for("anything.test", "127.0.0.3".parse().unwrap(), now)
                .is_some()
        );
        assert!(
            policy
                .temporary_allow_for("anything.test", "192.0.2.1".parse().unwrap(), now)
                .is_none()
        );
        assert!(
            policy
                .temporary_allow_for(
                    "ads.test",
                    "127.0.0.1".parse().unwrap(),
                    now + Duration::from_secs(61)
                )
                .is_none()
        );
        assert!(
            policy
                .temporary_allow_for("ads.test", "127.0.0.1".parse().unwrap(), now)
                .is_none()
        );
        config.policies[0].temporary_exceptions[0].expires_at =
            expiry + MAX_EXCEPTION_REMAINING.as_secs();
        let mut changed = config.clone();
        changed.policies[0].temporary_exceptions[0].clients.clear();
        assert!(changed.validate_new_exceptions(&[&config]).is_err());
        changed = config.clone();
        changed.policies[0].temporary_exceptions[0].include_subdomains = true;
        assert!(changed.validate_new_exceptions(&[&config]).is_err());
    }
    fn clock() -> Clock {
        Clock {
            monotonic: Instant::now(),
            wall: UNIX_EPOCH + Duration::from_secs(1000),
        }
    }
    fn input(expires_at: u64) -> TemporaryException {
        TemporaryException {
            clients: vec![],
            include_subdomains: false,
            name: "repair".into(),
            domain: "BÜCHER.TEST.".into(),
            expires_at,
        }
    }
    #[test]
    fn expiry_is_exact_ttl_is_floored_and_clock_jumps_never_revive_entries() {
        let clock = clock();
        let entries = Entries::compile(0, &[input(1005)], &clock)
            .unwrap()
            .unwrap();
        let entry = &entries.0.get("xn--bcher-kva.test").unwrap()[0];
        assert_eq!(entry.remaining_at(clock.monotonic, clock.wall), Some(5));
        assert_eq!(
            entry.remaining_at(
                clock.monotonic + Duration::from_millis(4200),
                clock.wall + Duration::from_millis(4200)
            ),
            Some(0)
        );
        assert_eq!(
            entry.remaining_at(
                clock.monotonic + Duration::from_secs(5),
                clock.wall - Duration::from_secs(100)
            ),
            None
        );
        assert_eq!(entry.remaining_at(clock.monotonic, clock.wall), None);
        let entries = Entries::compile(0, &[input(1005)], &clock)
            .unwrap()
            .unwrap();
        let entry = entries.0.values().flatten().next().unwrap();
        assert_eq!(
            entry.remaining_at(clock.monotonic, clock.wall + Duration::from_secs(5)),
            None
        );
        assert_eq!(entry.remaining_at(clock.monotonic, clock.wall), None);
        let later = Clock {
            wall: clock.wall + Duration::from_secs(6),
            ..clock
        };
        assert!(
            Entries::compile(0, &[input(1005)], &later)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn names_domains_limits_and_expired_entries_are_validated() {
        let clock = clock();
        assert!(Entries::compile(0, &[], &clock).unwrap().is_none());
        assert!(
            Entries::compile(0, &[input(999)], &clock)
                .unwrap()
                .is_none()
        );
        assert!(
            Entries::compile(
                0,
                &[input(1000 + MAX_EXCEPTION_REMAINING.as_secs())],
                &clock
            )
            .is_ok()
        );
        assert!(Entries::compile(0, &[input(u64::MAX)], &clock).is_err());
        assert!(Entries::compile(0, &[input(0)], &clock).is_err());
        let mut other = input(1005);
        other.name = "other".into();
        other.domain = "xn--bcher-kva.test".into();
        assert!(Entries::compile(0, &[input(1005), other.clone()], &clock).is_err());
        other.domain = "different.test".into();
        other.name = "repair".into();
        assert!(Entries::compile(0, &[input(1005), other], &clock).is_err());
        let mut expired = input(999);
        expired.domain = "bad..test".into();
        assert!(Entries::compile(0, &[expired], &clock).is_err());
    }
    #[test]
    fn lagging_wall_clock_clamps_the_deadline_instead_of_failing_compilation() {
        // A revision accepted with a correct clock, restored on a board whose
        // clock is a year behind: compilation must succeed.
        let clock = clock();
        let year = 365 * 86400;
        let entries = Entries::compile(0, &[input(1000 + year)], &clock)
            .unwrap()
            .unwrap();
        let entry = entries.0.values().flatten().next().unwrap();
        assert_eq!(entry.deadline, clock.monotonic + MAX_EXCEPTION_REMAINING);
        assert_eq!(
            entry.remaining_at(clock.monotonic, clock.wall),
            Some(u32::try_from(MAX_EXCEPTION_REMAINING.as_secs()).unwrap())
        );
        // Once NTP corrects the clock the absolute expiry governs again.
        let corrected = clock.wall + Duration::from_secs(year - 10);
        assert_eq!(
            entry.remaining_at(clock.monotonic + Duration::from_secs(1), corrected),
            Some(10)
        );
        assert_eq!(
            entry.remaining_at(
                clock.monotonic + Duration::from_secs(2),
                corrected + Duration::from_secs(10)
            ),
            None
        );
        // Whole-snapshot compilation with the real clock behaves the same way.
        let mut config = PolicyConfigSet::default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        config.policies[0].temporary_exceptions = vec![TemporaryException {
            expires_at: now + 30 * 86400,
            ..input(0)
        }];
        let snapshot = crate::PolicySnapshot::compile(config, 1).unwrap();
        let found = snapshot.policies()[0]
            .temporary_allow("xn--bcher-kva.test", Instant::now())
            .unwrap();
        assert!(
            found.remaining_ttl(Instant::now()).unwrap()
                <= u32::try_from(MAX_EXCEPTION_REMAINING.as_secs()).unwrap()
        );
    }
    #[test]
    fn intake_limits_only_new_exceptions_to_seven_days() {
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        let week = MAX_EXCEPTION_REMAINING.as_secs();
        let config = |expires_at| {
            let mut config = PolicyConfigSet::default();
            config.policies[0].temporary_exceptions = vec![input(expires_at)];
            config
        };
        for expires_at in [1, 999, 1000, 1000 + week, u64::MAX] {
            assert!(
                config(expires_at)
                    .validate_new_exceptions_at(&[], now)
                    .is_ok(),
                "{expires_at}"
            );
        }
        let long = config(1001 + week);
        assert_eq!(
            long.validate_new_exceptions_at(&[], now)
                .unwrap_err()
                .to_string(),
            "invalid configuration: policies[0].temporary_exceptions[0].expires_at: \
             exception \"repair\" has more than seven days remaining"
        );
        // Already accepted (for example, active while the clock was correct).
        assert!(long.validate_new_exceptions_at(&[&long], now).is_ok());
        let unrelated = PolicyConfigSet::default();
        assert!(
            long.validate_new_exceptions_at(&[&unrelated, &long], now)
                .is_ok()
        );
        // Any change to the accepted identity is a new exception.
        for changed in [
            config(1002 + week),
            {
                let mut renamed = long.clone();
                renamed.policies[0].name = "other".into();
                renamed
            },
            {
                let mut renamed = long.clone();
                renamed.policies[0].temporary_exceptions[0].name = "other".into();
                renamed
            },
        ] {
            assert!(changed.validate_new_exceptions_at(&[&long], now).is_err());
        }
    }
    #[test]
    fn permanent_assertions_cannot_be_satisfied_by_an_exception_and_counts_are_bounded() {
        use crate::{Assertion, PolicyConfigSet, PolicySnapshot};
        use rustwalld_dns_filter::{Action, ListInput};
        let mut config = PolicyConfigSet::default();
        config.policies[0].lists = vec![ListInput {
            syntax: Default::default(),
            name: "deny".into(),
            action: Action::Block,
            rules: "ads.test".into(),
        }];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        config.policies[0].temporary_exceptions = vec![TemporaryException {
            clients: vec![],
            include_subdomains: false,
            name: "repair".into(),
            domain: "ADS.TEST.".into(),
            expires_at,
        }];
        config.assertions = vec![Assertion {
            qtype: 1,
            client: "127.0.0.1".parse().unwrap(),
            domain: "ads.test".into(),
            expected: Action::Block,
        }];
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        let trace = snapshot
            .explain("127.0.0.1".parse().unwrap(), "ads.test")
            .unwrap();
        assert_eq!(trace.decision.action, Action::Allow);
        assert_eq!(trace.temporary_exception.unwrap().name, "repair");
        assert!(trace.rule.is_none());
        assert_eq!(
            snapshot
                .explain("127.0.0.1".parse().unwrap(), "sub.ads.test")
                .unwrap()
                .decision
                .action,
            Action::Block
        );
        let report = PolicySnapshot::check(config.clone()).unwrap();
        assert!(report.valid);
        assert_eq!(report.basis, "permanent_policy");
        assert_eq!(
            report.results[0].trace.as_ref().unwrap().decision.action,
            Action::Block
        );
        config.assertions[0].expected = Action::Allow;
        assert!(PolicySnapshot::compile(config.clone(), 2).is_err());
        assert_eq!(PolicySnapshot::check(config.clone()).unwrap().failed, 1);
        config.assertions.clear();
        config.policies[0].temporary_exceptions = (0..1025)
            .map(|i| TemporaryException {
                clients: vec![],
                include_subdomains: false,
                name: format!("e{i}"),
                domain: format!("d{i}.test"),
                expires_at,
            })
            .collect();
        assert!(PolicySnapshot::compile(config.clone(), 3).is_err());
        config.policies[0].temporary_exceptions.pop();
        assert!(PolicySnapshot::compile(config.clone(), 3).is_ok());
        let policy = config.policies[0].clone();
        for i in 0..3 {
            let mut extra = policy.clone();
            extra.name = format!("p{i}");
            config.policies.push(extra);
        }
        assert!(PolicySnapshot::compile(config.clone(), 4).is_ok());
        let mut extra = policy;
        extra.name = "over-limit".into();
        extra.temporary_exceptions.truncate(1);
        config.policies.push(extra);
        assert!(PolicySnapshot::compile(config, 5).is_err());
    }
}
