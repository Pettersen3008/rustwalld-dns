#![no_main]
use filtering::{Action, FilterSnapshot, ListInput};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &str| {
    if input.len() > 8192 {
        return;
    }
    if let Ok(snapshot) = FilterSnapshot::compile(
        &[ListInput {
            name: "fuzz".into(),
            action: Action::Block,
            rules: input.into(),
        }],
        256,
        8192,
    ) {
        for rule in snapshot.rules() {
            let _ = snapshot.evaluate(&rule.domain);
        }
    }
});
