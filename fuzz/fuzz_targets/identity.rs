#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input:&[u8]| {let _=rustwalld_dns::auth::validate_document(input);});
