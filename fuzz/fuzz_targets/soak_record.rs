#![no_main]
use libfuzzer_sys::fuzz_target;
// Reuse the exact example intake without exposing a production API for tooling.
// Filesystem/CLI entry points are intentionally unused: this target is pure parsing.
#[allow(
    dead_code,
    reason = "example includes filesystem helpers; fuzzing never opens files"
)]
#[path = "../../crates/app/examples/support/soak_record.rs"]
mod soak_record;
#[allow(
    dead_code,
    reason = "sample file reading is excluded from pure fuzzing"
)]
#[path = "../../crates/app/examples/support/soak_samples.rs"]
mod soak_samples;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 256 * 1024 {
        return;
    }
    if bytes.len() <= 65535 {
        let _ = soak_record::complete_message(bytes);
    }
    if let Ok(prepared) = soak_record::Prepared::parse(bytes.to_vec()) {
        assert!(prepared.templates.len() <= 32);
        if let Ok(encoded) = serde_json::to_vec(&prepared.record) {
            assert!(soak_record::Prepared::parse(encoded).is_ok());
        }
    }
    if bytes.len() <= 16 * 1024
        && let Ok(sample) = serde_json::from_slice::<soak_samples::Sample>(bytes)
        && let Ok(fixture) =
            soak_record::Prepared::parse(include_bytes!("../seeds/soak_record/run.json").to_vec())
    {
        let _ = sample.validate(&fixture.record, &fixture.record.phases[0], sample.unix_ms);
        let _ = soak_samples::continuity(&sample, &sample);
        let mut summary = soak_samples::Summary::default();
        let _ = summary.record(None, sample);
    }
});
