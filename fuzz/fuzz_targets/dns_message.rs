#![no_main]
use hickory_proto::op::Message;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65535 {
        return;
    }
    if let Ok(message) = Message::from_vec(bytes) {
        if let Ok(encoded) = message.to_vec() {
            let _ = Message::from_vec(&encoded);
        }
    }
});
