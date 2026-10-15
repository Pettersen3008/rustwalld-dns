#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input:&[u8]| {
    let Some((&mode,data))=input.split_first() else {return;};
    let Some(offset)=data.windows(2).position(|bytes|bytes==b"\0\0") else {return;};
    let _=rustwalld_dns::tls::from_pem(&data[..offset],&data[offset+2..],mode & 1 != 0);
});
