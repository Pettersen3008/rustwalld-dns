//! Compiled exact-domain allows. Expiry never depends on a management task.
use crate::{
    CompiledPolicy, PolicyError,
    config::{excerpt, validate_name},
    sources::MAX_UNIX_SECONDS,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MAX_EXCEPTION_REMAINING: Duration = Duration::from_secs(7 * 86400);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporaryException {
    pub name: String,
    pub domain: String,
    pub expires_at: u64,
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
pub(crate) struct Entries(HashMap<String, Entry>);

pub struct TemporaryMatch<'a> {
    pub index: u16,
    pub exception: &'a TemporaryException,
    entry: &'a Entry,
}
impl TemporaryMatch<'_> {
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
            Some(monotonic.min(wall).as_secs().min(u32::MAX as u64) as u32)
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
            let domain = rustwalld_dns_filter::normalize(&input.domain)
                .map_err(|_| PolicyError::field(field("domain"), excerpt(&input.domain)))?;
            if !names.insert(&input.name) {
                return Err(PolicyError::field(
                    field("name"),
                    format!("duplicate exception name {}", excerpt(&input.name)),
                ));
            }
            if !domains.insert(domain.clone()) {
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
            if remaining > MAX_EXCEPTION_REMAINING {
                return Err(PolicyError::field(
                    field("expires_at"),
                    "more than seven days remaining",
                ));
            }
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
            entries.insert(
                domain,
                Entry {
                    index,
                    exception,
                    wall,
                    deadline,
                    expired: AtomicBool::new(false),
                },
            );
        }
        Ok((!entries.is_empty()).then_some(Self(entries)))
    }
}
impl CompiledPolicy {
    /// Name is normalized ASCII without a root dot. No allocation or global lock.
    pub fn temporary_allow(&self, domain: &str, now: Instant) -> Option<TemporaryMatch<'_>> {
        let entry = self.exceptions.as_ref()?.0.get(domain)?;
        if entry.expired.load(Ordering::Relaxed) {
            return None;
        }
        if now >= entry.deadline {
            entry.expired.store(true, Ordering::Relaxed);
            return None;
        }
        let found = TemporaryMatch {
            index: entry.index,
            exception: &entry.exception,
            entry,
        };
        found.remaining_ttl(now)?;
        Some(found)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn clock() -> Clock {
        Clock {
            monotonic: Instant::now(),
            wall: UNIX_EPOCH + Duration::from_secs(1000),
        }
    }
    fn input(expires_at: u64) -> TemporaryException {
        TemporaryException {
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
        let entry = entries.0.get("xn--bcher-kva.test").unwrap();
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
        let entry = entries.0.values().next().unwrap();
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
        assert!(
            Entries::compile(
                0,
                &[input(1001 + MAX_EXCEPTION_REMAINING.as_secs())],
                &clock
            )
            .is_err()
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
    fn permanent_assertions_cannot_be_satisfied_by_an_exception_and_counts_are_bounded() {
        use crate::{Assertion, PolicyConfigSet, PolicySnapshot};
        use rustwalld_dns_filter::{Action, ListInput};
        let mut config = PolicyConfigSet::default();
        config.policies[0].lists = vec![ListInput {
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
            name: "repair".into(),
            domain: "ADS.TEST.".into(),
            expires_at,
        }];
        config.assertions = vec![Assertion {
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
