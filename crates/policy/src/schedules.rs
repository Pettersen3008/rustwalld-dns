//! Offline weekly compilation and bounded civil-minute selection.
use crate::{CompiledPolicy, PolicyError};
use chrono::{Datelike, Timelike, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
/// Bundled IANA data version used by this deployed policy library.
pub const SCHEDULE_TZDB_VERSION: &str = chrono_tz::IANA_TZDB_VERSION;

/// A local day on which a weekly window starts.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleDay {
    /// Monday.
    Mon,
    /// Tuesday.
    Tue,
    /// Wednesday.
    Wed,
    /// Thursday.
    Thu,
    /// Friday.
    Fri,
    /// Saturday.
    Sat,
    /// Sunday.
    Sun,
}
impl ScheduleDay {
    fn index(self) -> usize {
        self as usize
    }
}
/// Meaning of the listed weekly windows.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleMode {
    /// Block selected service domains inside windows.
    #[default]
    Block,
    /// Allow selected service domains inside windows; block outside.
    Allow,
}
/// One half-open civil-time window; overnight ranges continue on the next day.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleWindow {
    /// Unique days on which this window starts.
    pub days: Vec<ScheduleDay>,
    /// Local HH:MM, from 00:00 to 23:59.
    pub start: String,
    /// Local HH:MM; 24:00 is allowed for end only.
    pub end: String,
}
/// A weekly service schedule. Names and times are parsed only during compilation.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeeklySchedule {
    /// Explicit bundled IANA zone name; never the host's implicit Local zone.
    pub time_zone: String,
    /// Block within windows (default), or allow within them.
    #[serde(default)]
    pub mode: ScheduleMode,
    /// Explicit windows, at most 32; overlaps are unioned. Empty is intentional.
    pub windows: Vec<ScheduleWindow>,
}
/// State actually used to produce a scheduled reply and its rule identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceScheduleState {
    /// Selected service groups are not enforced now.
    Inactive,
    /// Selected service groups are enforced now.
    Active,
    /// Unusable wall clock; groups are enforced with TTL zero.
    InvalidClock,
}
impl ServiceScheduleState {
    /// Which immutable filter set applies.
    pub fn blocking(self) -> bool {
        self != Self::Inactive
    }
    /// Stable integer representation for durable telemetry adapters.
    pub fn code(self) -> u8 {
        match self {
            Self::Inactive => 0,
            Self::Active => 1,
            Self::InvalidClock => 2,
        }
    }
    /// Read a stable telemetry code, refusing unknown values.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Inactive),
            1 => Some(Self::Active),
            2 => Some(Self::InvalidClock),
            _ => None,
        }
    }
}
/// Minute state and a conservative private reply TTL cap.
#[derive(Clone, Copy, Debug)]
pub struct ScheduleEvaluation {
    /// Actual filter variant.
    pub state: ServiceScheduleState,
    /// Floor seconds until the next civil minute, zero for invalid time.
    pub ttl_cap: u32,
}
/// Current schedule diagnostics, separate from permanent assertions.
#[derive(Serialize)]
pub struct ScheduleExplanation<'a> {
    /// Configured zone, not a browser or host-local guess.
    pub time_zone: &'a str,
    /// Actual state at the sampled instant.
    pub state: ServiceScheduleState,
    /// Conservative TTL cap.
    pub ttl_cap: u32,
}
pub(crate) struct CompiledSchedule {
    zone: Tz,
    bits: [u64; 158],
}
fn minute(text: &str, end: bool) -> Result<usize, PolicyError> {
    let bytes = text.as_bytes();
    if bytes.len() != 5
        || bytes[2] != b':'
        || ![bytes[0], bytes[1], bytes[3], bytes[4]]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return Err(PolicyError::field(
            "blocked_services.schedule.windows",
            "times must be HH:MM",
        ));
    }
    let hour = usize::from(bytes[0] - b'0') * 10 + usize::from(bytes[1] - b'0');
    let minutes = usize::from(bytes[3] - b'0') * 10 + usize::from(bytes[4] - b'0');
    if minutes >= 60 || hour > 23 && !(end && hour == 24 && minutes == 0) {
        return Err(PolicyError::field(
            "blocked_services.schedule.windows",
            "time is outside the allowed day",
        ));
    }
    Ok(hour * 60 + minutes)
}
impl WeeklySchedule {
    /// Validate the bounded input without publishing or performing I/O.
    pub fn validate(&self) -> Result<(), PolicyError> {
        CompiledSchedule::compile(self).map(|_| ())
    }
}
impl CompiledSchedule {
    pub(crate) fn compile(input: &WeeklySchedule) -> Result<Self, PolicyError> {
        if input.time_zone.len() > 128 || !input.time_zone.is_ascii() || input.time_zone == "Local"
        {
            return Err(PolicyError::field(
                "blocked_services.schedule.time_zone",
                "explicit IANA time zone required",
            ));
        }
        let zone = input.time_zone.parse::<Tz>().map_err(|_| {
            PolicyError::field(
                "blocked_services.schedule.time_zone",
                "unknown bundled IANA time zone",
            )
        })?;
        PolicyError::check_count(
            || "blocked_services.schedule.windows".into(),
            input.windows.len(),
            0,
            32,
        )?;
        let mut compiled = Self {
            zone,
            bits: [0; 158],
        };
        for window in &input.windows {
            PolicyError::check_count(
                || "blocked_services.schedule.windows.days".into(),
                window.days.len(),
                1,
                7,
            )?;
            let start = minute(&window.start, false)?;
            let end = minute(&window.end, true)?;
            if start == end {
                return Err(PolicyError::field(
                    "blocked_services.schedule.windows",
                    "equal start/end is ambiguous; use 00:00 to 24:00 for a whole day",
                ));
            }
            let mut seen = [false; 7];
            for day in &window.days {
                let index = day.index();
                if seen[index] {
                    return Err(PolicyError::field(
                        "blocked_services.schedule.windows.days",
                        "duplicate day",
                    ));
                }
                seen[index] = true;
                let stop = if end < start { end + 1440 } else { end };
                for offset in start..stop {
                    let minute = (index * 1440 + offset) % 10080;
                    compiled.bits[minute / 64] |= 1u64 << (minute % 64);
                }
            }
        }
        if input.mode == ScheduleMode::Allow {
            for word in &mut compiled.bits {
                *word = !*word;
            }
        }
        Ok(compiled)
    }
    pub(crate) fn evaluate(&self, now: SystemTime) -> ScheduleEvaluation {
        let invalid = ScheduleEvaluation {
            state: ServiceScheduleState::InvalidClock,
            ttl_cap: 0,
        };
        let Ok(elapsed) = now.duration_since(UNIX_EPOCH) else {
            return invalid;
        };
        // Keeps conversion far from representational edges and rejects unsynced RTCs.
        if !(946684800..4102444800).contains(&elapsed.as_secs()) {
            return invalid;
        }
        let Ok(seconds) = i64::try_from(elapsed.as_secs()) else {
            return invalid;
        };
        let Some(utc) = chrono::DateTime::<Utc>::from_timestamp(seconds, elapsed.subsec_nanos())
        else {
            return invalid;
        };
        let local = utc.with_timezone(&self.zone);
        let minute = local.weekday().num_days_from_monday() as usize * 1440
            + local.hour() as usize * 60
            + local.minute() as usize;
        let active = self.bits[minute / 64] & (1u64 << (minute % 64)) != 0;
        ScheduleEvaluation {
            state: if active {
                ServiceScheduleState::Active
            } else {
                ServiceScheduleState::Inactive
            },
            ttl_cap: 60 - local.second() - u32::from(local.nanosecond() > 0),
        }
    }
}
impl CompiledPolicy {
    /// Whether this policy needs civil-time selection.
    pub fn has_service_schedule(&self) -> bool {
        self.schedule.is_some()
    }
    /// Read a compiled bitmap using the caller's trusted wall-clock sample.
    pub fn service_schedule_at(&self, now: SystemTime) -> Option<ScheduleEvaluation> {
        self.schedule
            .as_ref()
            .map(|schedule| schedule.evaluate(now))
    }
    /// Select immutable service-on or user-list-only filters. Never parses input.
    pub fn filters_for_services(&self, active: bool) -> &rustwalld_dns_filter::FilterSnapshot {
        if active {
            &self.filters
        } else {
            self.services_off.as_deref().unwrap_or(&self.filters)
        }
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn schedule(zone: &str, days: Vec<ScheduleDay>, start: &str, end: &str) -> WeeklySchedule {
        WeeklySchedule {
            time_zone: zone.into(),
            mode: ScheduleMode::Block,
            windows: vec![ScheduleWindow {
                days,
                start: start.into(),
                end: end.into(),
            }],
        }
    }
    fn at(text: &str) -> SystemTime {
        let dt = chrono::DateTime::parse_from_rfc3339(text).unwrap();
        UNIX_EPOCH
            + std::time::Duration::from_secs(dt.timestamp() as u64)
            + std::time::Duration::from_nanos(dt.timestamp_subsec_nanos() as u64)
    }
    #[test]
    fn exact_subsecond_edges_overnight_and_week_wrap() {
        let input = schedule("UTC", vec![ScheduleDay::Sun], "22:00", "07:00");
        let compiled = CompiledSchedule::compile(&input).unwrap();
        for text in ["2026-10-11T22:00:00Z", "2026-10-12T06:59:59.999Z"] {
            assert!(compiled.evaluate(at(text)).state.blocking());
        }
        for text in [
            "2026-10-11T21:59:59Z",
            "2026-10-12T07:00:00Z",
            "2026-10-13T01:00:00Z",
        ] {
            assert_eq!(
                compiled.evaluate(at(text)).state,
                ServiceScheduleState::Inactive
            );
        }
        assert_eq!(compiled.evaluate(at("2026-10-12T06:59:59.999Z")).ttl_cap, 0);
        assert_eq!(compiled.evaluate(at("2026-10-12T06:59:50Z")).ttl_cap, 10);
    }
    #[test]
    fn named_zone_dst_folds_gaps_and_non_hour_offsets_use_civil_minutes() {
        let compiled = CompiledSchedule::compile(&schedule(
            "Europe/Oslo",
            vec![ScheduleDay::Sun],
            "02:00",
            "03:00",
        ))
        .unwrap();
        for text in ["2026-10-25T00:30:00Z", "2026-10-25T01:30:00Z"] {
            assert!(compiled.evaluate(at(text)).state.blocking());
        }
        for text in [
            "2026-03-29T00:59:59Z",
            "2026-03-29T01:00:00Z",
            "2026-10-25T02:00:00Z",
        ] {
            assert_eq!(
                compiled.evaluate(at(text)).state,
                ServiceScheduleState::Inactive
            );
        }
        let kathmandu = CompiledSchedule::compile(&schedule(
            "Asia/Kathmandu",
            vec![ScheduleDay::Mon],
            "09:00",
            "10:00",
        ))
        .unwrap();
        assert!(
            kathmandu
                .evaluate(at("2026-10-12T03:15:00Z"))
                .state
                .blocking()
        );
    }
    #[test]
    fn empty_modes_overlap_invalid_clock_and_bad_inputs_are_explicit() {
        assert!(serde_json::from_str::<WeeklySchedule>(r#"{"time_zone":"UTC"}"#).is_err());
        let mut input = schedule("UTC", vec![ScheduleDay::Mon], "00:00", "24:00");
        input.windows.clear();
        assert_eq!(
            CompiledSchedule::compile(&input)
                .unwrap()
                .evaluate(at("2026-10-12T09:00:00Z"))
                .state,
            ServiceScheduleState::Inactive
        );
        input.mode = ScheduleMode::Allow;
        assert!(
            CompiledSchedule::compile(&input)
                .unwrap()
                .evaluate(at("2026-10-12T09:00:00Z"))
                .state
                .blocking()
        );
        let compiled = CompiledSchedule::compile(&input).unwrap();
        for now in [UNIX_EPOCH, at("2100-01-01T00:00:00Z")] {
            assert_eq!(
                compiled.evaluate(now).state,
                ServiceScheduleState::InvalidClock
            );
            assert_eq!(compiled.evaluate(now).ttl_cap, 0);
        }
        for (start, end) in [
            ("24:00", "00:00"),
            ("9:00", "10:00"),
            ("00:60", "02:00"),
            ("01:00", "01:00"),
        ] {
            assert!(
                CompiledSchedule::compile(&schedule("UTC", vec![ScheduleDay::Mon], start, end))
                    .is_err()
            );
        }
        assert!(
            CompiledSchedule::compile(&schedule("Local", vec![ScheduleDay::Mon], "00:00", "24:00"))
                .is_err()
        );
        assert!(
            CompiledSchedule::compile(&schedule(
                "UTC",
                vec![ScheduleDay::Mon, ScheduleDay::Mon],
                "00:00",
                "24:00"
            ))
            .is_err()
        );
        input = schedule("UTC", vec![ScheduleDay::Mon], "09:00", "11:00");
        input.windows.push(ScheduleWindow {
            days: vec![ScheduleDay::Mon],
            start: "10:00".into(),
            end: "12:00".into(),
        });
        assert!(
            CompiledSchedule::compile(&input)
                .unwrap()
                .evaluate(at("2026-10-12T11:30:00Z"))
                .state
                .blocking()
        );
        input.windows = vec![input.windows[0].clone(); 33];
        assert!(CompiledSchedule::compile(&input).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod policy_tests {
    use super::*;
    use crate::{Assertion, BlockedServices, PolicyConfigSet, PolicySnapshot};
    use rustwalld_dns_filter::{Action, ListInput};
    use std::sync::Arc;
    #[test]
    fn permanent_assertions_current_states_sharing_and_recorded_inputs_agree() {
        let mut config = PolicyConfigSet::default();
        config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
        config.policies[0].lists = vec![ListInput {
            name: "manual".into(),
            action: Action::Block,
            rules: "reddit.com".into(),
            syntax: Default::default(),
        }];
        config.policies[0].blocked_services = Some(BlockedServices {
            catalog_version: 1,
            ids: vec!["youtube".into(), "reddit".into()],
            schedule: Some(WeeklySchedule {
                time_zone: "UTC".into(),
                mode: ScheduleMode::Block,
                windows: vec![],
            }),
        });
        config.assertions = vec![Assertion {
            qtype: 1,
            client: "127.0.0.1".parse().unwrap(),
            domain: "www.youtube.com".into(),
            expected: Action::Block,
        }];
        let mut other = config.policies[0].clone();
        other.name = "other".into();
        config.policies.push(other);
        let snapshot = PolicySnapshot::compile(config, 1).unwrap();
        assert!(Arc::ptr_eq(
            snapshot.policies()[0].schedule.as_ref().unwrap(),
            snapshot.policies()[1].schedule.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            snapshot.policies()[0].services_off.as_ref().unwrap(),
            snapshot.policies()[1].services_off.as_ref().unwrap()
        ));
        let now = UNIX_EPOCH + std::time::Duration::from_secs(1791795600);
        let current = snapshot
            .explain_at("127.0.0.1".parse().unwrap(), "www.youtube.com", now)
            .unwrap();
        assert_eq!(current.decision.action, Action::Allow);
        assert_eq!(
            current.service_schedule.unwrap().state,
            ServiceScheduleState::Inactive
        );
        let manual = snapshot
            .explain_at("127.0.0.1".parse().unwrap(), "www.reddit.com", now)
            .unwrap();
        assert_eq!(manual.decision.action, Action::Block);
        assert_eq!(manual.rule.unwrap().sources.len(), 1);
        assert_eq!(manual.rule.unwrap().sources[0].list.as_ref(), "manual");
        let inputs = snapshot.config().policies[0]
            .filter_inputs_for_services(false)
            .unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(
            snapshot.policies()[0]
                .filters()
                .evaluate("www.youtube.com")
                .action,
            Action::Block
        );
    }
}
