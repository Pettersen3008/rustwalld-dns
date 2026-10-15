//! Conservative source schedule facts, not a port of AdGuard's scheduler.
use super::{Report, Severity};
use rustwalld_dns_policy::{ScheduleDay, ScheduleMode, ScheduleWindow, WeeklySchedule};
use serde_json::Value;
const DAYS: [(&str, ScheduleDay); 7] = [
    ("mon", ScheduleDay::Mon),
    ("tue", ScheduleDay::Tue),
    ("wed", ScheduleDay::Wed),
    ("thu", ScheduleDay::Thu),
    ("fri", ScheduleDay::Fri),
    ("sat", ScheduleDay::Sat),
    ("sun", ScheduleDay::Sun),
];
pub(super) fn validate(value: &Value, path: &str) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let Some(object) = value.as_object() else {
        return Err(format!("{path} must be a mapping"));
    };
    if object
        .get("time_zone")
        .is_some_and(|value| !value.is_string())
    {
        return Err(format!("{path}.time_zone must be a string"));
    }
    for (key, _) in DAYS {
        if let Some(day) = object.get(key).filter(|value| !value.is_null()) {
            if !day.is_object() {
                return Err(format!("{path}.{key} must be a mapping"));
            }
            for field in ["start", "end"] {
                if day
                    .get(field)
                    .is_some_and(|value| !value.is_string() && !value.is_number())
                {
                    return Err(format!("{path}.{key}.{field} must be a duration"));
                }
            }
        }
    }
    Ok(())
}
fn minutes(value: &Value, json_source: bool) -> Option<u64> {
    if json_source && value.is_number() {
        let milliseconds = value.as_f64()?;
        if !milliseconds.is_finite()
            || !(0.0..=86400000.0).contains(&milliseconds)
            || milliseconds % 60000.0 != 0.0
        {
            return None;
        }
        return Some((milliseconds / 60000.0) as u64);
    }
    let text = value.as_str()?;
    if text.len() > 32 || !text.is_ascii() {
        return None;
    }
    if matches!(text, "0" | "0s") {
        return Some(0);
    }
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut total = 0u64;
    while index < bytes.len() {
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start || index == bytes.len() {
            return None;
        }
        let number = text[start..index].parse::<u64>().ok()?;
        let amount = match bytes[index] {
            b'h' => number.checked_mul(60)?,
            b'm' => number,
            b's' if number % 60 == 0 => number / 60,
            _ => return None,
        };
        index += 1;
        total = total.checked_add(amount)?;
        if total > 1440 {
            return None;
        }
    }
    Some(total)
}
pub(super) fn translate(
    value: &Value,
    path: &str,
    json_source: bool,
    report: &mut Report,
) -> Result<Option<WeeklySchedule>, String> {
    validate(value, path)?;
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    if object.is_empty() {
        return Ok(None);
    }
    report.unreviewed(
        value,
        path,
        &["time_zone", "mon", "tue", "wed", "thu", "fri", "sat", "sun"],
        &[],
    );
    let mut windows = Vec::new();
    let mut unsupported = false;
    for (key, day) in DAYS {
        let Some(range) = object.get(key).filter(|value| !value.is_null()) else {
            continue;
        };
        report.unreviewed(range, &format!("{path}.{key}"), &["start", "end"], &[]);
        let bounds = minutes(&range["start"], json_source).zip(minutes(&range["end"], json_source));
        match bounds {
            Some((0, 0)) => {}
            Some((start, end)) if start < end && start < 1440 => windows.push(ScheduleWindow {
                days: vec![day],
                start: format!("{:02}:{:02}", start / 60, start % 60),
                end: format!("{:02}:{:02}", end / 60, end % 60),
            }),
            _ => {
                unsupported = true;
                report.issue(format!("{path}.{key}"),Severity::Blocker,"Source interval is absent, invalid or outside the supported minute-aligned duration formats; no partial schedule was applied.");
            }
        }
    }
    if unsupported {
        return Ok(None);
    }
    if windows.is_empty() {
        return Ok(None);
    }
    let Some(zone) = object
        .get("time_zone")
        .and_then(Value::as_str)
        .filter(|zone| !zone.is_empty() && *zone != "Local")
    else {
        report.issue(format!("{path}.time_zone"),Severity::Blocker,"Source zone is missing or Local; choose an explicit destination zone instead of guessing the source host clock.");
        return Ok(None);
    };
    let schedule = WeeklySchedule {
        time_zone: zone.into(),
        mode: ScheduleMode::Allow,
        windows,
    };
    if schedule.validate().is_err() {
        report.issue(format!("{path}.time_zone"),Severity::Blocker,"Source zone is not supported by the bundled destination database; no schedule was applied.");
        return Ok(None);
    }
    if !["UTC", "Etc/UTC", "Etc/GMT", "GMT"].contains(&zone) {
        report.issue(path,Severity::Blocker,"Source elapsed-since-midnight periods can differ from destination civil-time windows on DST dates. The draft preserves clock hours for review, not guaranteed equivalent DST behavior.");
    }
    Ok(Some(schedule))
}
