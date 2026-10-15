#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns::{migration::{preview,Source}};
use rustwalld_dns_policy::PolicyConfigSet;
fuzz_target!(|data: &[u8]| {
    let Some((&source,input)) = data.split_first() else {return;};
    let _ = preview(if source & 1 == 0 {Source::Adguard} else {Source::Pihole},input,PolicyConfigSet::default());
});
