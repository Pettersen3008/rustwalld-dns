#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_filter::{Action, FilterSnapshot, ListInput, ParallelCompiler};
use std::sync::OnceLock;
// Test-only owned pool, reused across fuzz inputs; no global Rayon pool.
static COMPILER: OnceLock<ParallelCompiler> = OnceLock::new();
fuzz_target!(|input: &str| {
    const MAX_BYTES: usize = 512 * 1024;
    if input.len() > MAX_BYTES {
        return;
    }
    let compiler = COMPILER.get_or_init(|| ParallelCompiler::new(2).unwrap());
    let lists = [ListInput {
        name: "fuzz".into(),
        action: Action::Block,
        rules: input.into(),
    }];
    let limit = [0, 1, 256, 40000][usize::from(input.as_bytes().first().copied().unwrap_or(0) & 3)];
    match (
        FilterSnapshot::compile(&lists, limit, MAX_BYTES),
        compiler.compile(&lists, limit, MAX_BYTES),
    ) {
        (Ok(serial), Ok(parallel)) => {
            assert_eq!(
                serde_json::to_vec(serial.rules()).unwrap(),
                serde_json::to_vec(parallel.rules()).unwrap()
            );
            assert_eq!(
                serde_json::to_vec(&serial.stats).unwrap(),
                serde_json::to_vec(&parallel.stats).unwrap()
            );
            assert_eq!(serial.payload_bytes(), parallel.payload_bytes());
            assert_eq!(serial.effective_rules(), parallel.effective_rules());
            for rule in serial.rules() {
                assert_eq!(
                    serial.evaluate(&rule.domain),
                    parallel.evaluate(&rule.domain)
                );
                assert_eq!(
                    serial.evaluate(&format!("child.{}", rule.domain)),
                    parallel.evaluate(&format!("child.{}", rule.domain))
                );
            }
        }
        (Err(serial), Err(parallel)) => assert_eq!(serial.to_string(), parallel.to_string()),
        _ => panic!("sequential/parallel compilation diverged"),
    }
});
