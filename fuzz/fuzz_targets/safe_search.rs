#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_policy::{PolicyConfigSet,PolicySnapshot,SafeSearchConfig,YouTubeMode,LocalData,LocalRecord};
use hickory_proto::rr::RecordType;
fuzz_target!(|input:&[u8]| {
    if input.len()>8192 {return;}
    let Some((&flags,body))=input.split_first() else {return;};
    let settings=if body.starts_with(b"{") {
        let Ok(value)=serde_json::from_slice::<SafeSearchConfig>(body) else {return;};value
    } else {SafeSearchConfig{google:flags&1!=0,bing:flags&2!=0,duckduckgo:flags&4!=0,youtube:match (flags>>3)%3 {1=>YouTubeMode::Moderate,2=>YouTubeMode::Strict,_=>YouTubeMode::Off},catalog_version:if flags&128==0 {1} else {2}}};
    let mut config=PolicyConfigSet::default();config.upstreams[0].addresses=vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].safe_search=Some(settings);
    let text=std::str::from_utf8(body).unwrap_or("");
    if flags&32!=0 {config.policies[0].dns_records=vec![LocalRecord{domain:text.to_owned(),ttl:60,data:LocalData::Cname{target:"forcesafesearch.google.com".into()}}];}
    let Ok(snapshot)=PolicySnapshot::compile(config,1) else {return;};
    let policy=&snapshot.policies()[0];
    for domain in [text,"www.google.com","www.google.no","edgeservices.bing.com","duckduckgo.com","www.youtube.com","youtube.com"] {
        let _=snapshot.explain("127.0.0.1".parse().unwrap(),domain);
        for kind in [RecordType::A,RecordType::AAAA,RecordType::CNAME,RecordType::HTTPS,RecordType::TXT] {
            if let Some((records,target))=policy.safe_search_answer(domain,kind) {
                assert_eq!(records.len(),1);
                assert_eq!(target.is_none(),kind==RecordType::CNAME);
                assert_eq!(policy.safe_search_match(domain).unwrap().catalog_version,1);
            }
        }
    }
});
