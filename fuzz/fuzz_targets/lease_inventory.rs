#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    if input.len()>1024*1024 {return;}
    if let Ok(text)=std::str::from_utf8(input) {
        if let Ok(devices)=rustwalld_dns::integrations::parse_leases(text,100) {
            assert!(devices.len()<=4096);
            for device in devices {assert!(device.expires_at.is_none_or(|expiry|expiry>100));assert!(device.name.is_none_or(|name|name.len()<=256));}
        }
    }
});
