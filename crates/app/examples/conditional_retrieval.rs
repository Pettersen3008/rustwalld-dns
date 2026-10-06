//! Local authenticated list-transfer baseline. No public DNS or strict network gate.
#![allow(clippy::unwrap_used)]
#[path = "../tests/support/download_fixture.rs"]
mod download_fixture;
use rustwalld_dns::downloads::{self, Fetch};
use serde_json::json;
use std::{sync::atomic::Ordering, time::Instant};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let fixture = download_fixture::Fixture::start().await;
    let text: String = (0..100_000).map(|i| format!("=b{i}.test\n")).collect();
    fixture.conditional.lock().unwrap().text = text;
    let source = fixture.source("/conditional");
    let Fetch::Modified {
        stamp, validators, ..
    } = downloads::fetch_conditional(&source, None).await.unwrap()
    else {
        panic!("initial full GET required")
    };
    let mut full = Vec::new();
    let mut conditional = Vec::new();
    let mut full_bytes = 0;
    let mut conditional_bytes = 0;
    // Warm up both paths, alternate order to reduce one-way drift. Every request
    // uses a fresh authenticated HTTP/1.1 connection, matching the app downloader.
    for pair in 0..44 {
        for which in 0..2 {
            let is_conditional = (pair + which) % 2 == 0;
            let before = Instant::now();
            let result =
                downloads::fetch_conditional(&source, is_conditional.then_some(&validators))
                    .await
                    .unwrap();
            let elapsed = before.elapsed().as_nanos() as u64;
            let bytes = match result {
                Fetch::Modified { text, .. } => {
                    assert!(!is_conditional);
                    assert_eq!(text.len(), stamp.bytes);
                    text.len()
                }
                Fetch::NotModified { .. } => {
                    assert!(is_conditional);
                    0
                }
            };
            if pair >= 4 {
                if is_conditional {
                    conditional.push(elapsed);
                    conditional_bytes += bytes;
                } else {
                    full.push(elapsed);
                    full_bytes += bytes;
                }
            }
        }
    }
    fixture.wait_requests(89).await;
    fixture.wait_closed().await;
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 89);
    assert_eq!(fixture.open.load(Ordering::SeqCst), 0);
    fn summary(mut ns: Vec<u64>, bytes: usize) -> serde_json::Value {
        ns.sort_unstable();
        json!({"samples":ns.len(),"body_bytes":bytes,"p50_us":ns[ns.len()/2] as f64/1000.,"p95_us":ns[ns.len()*95/100] as f64/1000.,"min_us":ns[0] as f64/1000.,"max_us":ns[ns.len()-1] as f64/1000.})
    }
    println!(
        "{}",
        json!({"fixture_rules":100000,"fixture_bytes":stamp.bytes,"fixture_sha256":stamp.sha256,"transport":"pinned loopback HTTPS HTTP/1.1, new connection per request, alternating order, 4 warmup pairs", "full":summary(full,full_bytes),"conditional":summary(conditional,conditional_bytes)})
    );
}
