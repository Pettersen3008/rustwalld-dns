#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if let Ok(message) = rustwalld_dns_resolver::decode_dot_frame(bytes) {
        if let Ok(encoded) = message.to_vec() {
            assert!(rustwalld_dns_resolver::decode_dot_frame(&encoded).is_ok());
        }
    }
});
