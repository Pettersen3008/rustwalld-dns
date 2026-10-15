//! Local-only fixtures own and abort every listener/connection; no public DNS.
#![allow(clippy::unwrap_used, clippy::expect_used)] // Deterministic test fixtures.
use super::*;
use hickory_proto::{
    op::{Message, OpCode, Query},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use soak_record::{Run, Transport};
use soak_samples::{Sample, Summary, now_ms};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};

fn answer() -> Message {
    let name = Name::from_ascii("local.soak.test.").unwrap();
    let mut m = Message::response(0, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.metadata.recursion_available = true;
    m.add_query(Query::query(name.clone(), RecordType::A));
    m.add_answer(Record::from_rdata(name, 60, RData::A(A::new(192, 0, 2, 1))));
    m
}
fn hex(m: &Message) -> String {
    m.to_vec()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn record(dir: &Path, peers: &[SocketAddr]) -> Run {
    serde_json::from_value(json!({"format":1,"run_id":"local-fixture","seed":42,"mode":"qualification",
        "authority":{"instruction":"local fixture only","window":"bounded test","stop_owner":"test",
            "allowed_actions":"private sockets only","reversal":"close owned sockets"},
        "identity":{"revision":"0".repeat(40),"source_sha256":"0".repeat(64),"binary_sha256":"0".repeat(64),
            "dataset_sha256":"0".repeat(64),"appliance_config_sha256":"0".repeat(64),"controller_plan_sha256":"0".repeat(64),
            "appliance_limits":{"raw_cache":16,"decision_cache":16,"inflight":16,"udp_tasks":16,"upstream_waiters":16,"tcp_connections":16,"event_queue":16,"history":16},
            "platform":"test fixture","topology":"loopback",
            "clock_check":"same host","workload_basis":"synthetic; no representative claim"},
        "collector":{"path":dir.join("sample.json"),"target_id":"fixture","max_age_ms":2000},
        "limits":{"outstanding":8,"latency_us":400000,"resources":[1024,64,16,1048576,16,16],
            "artifact_bytes":8388608,"aggregate_bytes":4194304,"window_bytes":16384},
        "clients":[{"id":"client-1","bind":"127.0.0.1"}],
        "lanes":peers.iter().enumerate().map(|(i,p)|json!({"id":format!("lane-{i}"),"client":0,
            "endpoint":p,"transport":if i%2==0 {"udp"} else {"tcp"},"weight":1,
            "responses":[hex(&answer())],"ttl_floor":0,"tcp_fallback":false,"fresh":false})).collect::<Vec<_>>(),
        "phases":[{"id":"steady","seconds":1,"qps":10,"deadline_ms":500,"max_lag_ms":1000,
            "accepted":[0],"generations":[1],"allow_timeouts":false}],
        "external_checks":["fixture only; representative lab and fault matrix unverified"]})).unwrap()
}
fn prepare(r: &Run) -> Prepared {
    Prepared::parse(serde_json::to_vec(r).unwrap()).unwrap()
}
fn sample(r: &Run, seq: u64, requests: u64) -> Sample {
    Sample {
        run_id: r.run_id.clone(),
        target_id: r.collector.target_id.clone(),
        process_id: "123:456".into(),
        sequence: seq,
        unix_ms: now_ms().unwrap(),
        generation: 1,
        resources: [128, 4, 2, 4096, 1, 0],
        counters: BTreeMap::from([("requests".into(), requests)]),
    }
}
fn write_sample(r: &Run, s: &Sample) {
    let temp = r.collector.path.with_extension("next");
    std::fs::write(&temp, serde_json::to_vec(s).unwrap()).unwrap();
    std::fs::rename(temp, &r.collector.path).unwrap();
}
struct Collector(JoinHandle<()>);
impl Drop for Collector {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn collector(r: &Run, count: Arc<AtomicU64>) -> Collector {
    write_sample(r, &sample(r, 0, 0));
    let r = r.clone();
    Collector(tokio::spawn(async move {
        for seq in 1..10000 {
            sleep(Duration::from_millis(25)).await;
            write_sample(&r, &sample(&r, seq, count.load(Ordering::Relaxed)));
        }
    }))
}
#[derive(Clone, Copy)]
enum Behavior {
    Good,
    Wrong,
    Stall,
    Truncate,
    Malformed,
    Trailing,
    Reserved,
    Oversized,
    Late,
    Switch,
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Fixture {
    peer: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
    requests: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    names: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
fn reply(bytes: &[u8], behavior: Behavior, tcp: bool, ordinal: u64) -> Vec<u8> {
    if matches!(behavior, Behavior::Malformed) {
        return vec![0; 12];
    }
    let query = Message::from_vec(bytes).unwrap();
    let mut reply = answer();
    reply.metadata.id = query.metadata.id;
    reply.queries = query.queries.clone();
    reply.answers[0].name = query.queries[0].name().clone();
    if matches!(behavior, Behavior::Wrong)
        || (matches!(behavior, Behavior::Switch) && ordinal >= 10)
    {
        reply.answers[0].data = RData::A(A::new(192, 0, 2, 9));
    }
    if matches!(behavior, Behavior::Truncate) && !tcp {
        reply.metadata.truncation = true;
        reply.answers.clear();
    }
    if matches!(behavior, Behavior::Oversized) {
        for last in 2..=64 {
            reply.add_answer(Record::from_rdata(
                query.queries[0].name().clone(),
                60,
                RData::A(A::new(192, 0, 2, last)),
            ));
        }
    }
    let mut bytes = reply.to_vec().unwrap();
    if matches!(behavior, Behavior::Trailing) {
        bytes.extend_from_slice(b"unparsed suffix");
    }
    if matches!(behavior, Behavior::Reserved) {
        bytes[3] |= 0x40;
    }
    bytes
}
async fn fixture(behavior: Behavior) -> Fixture {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = tcp.local_addr().unwrap();
    let udp = Arc::new(UdpSocket::bind(peer).await.unwrap());
    let requests = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let names = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let (count, connections) = (requests.clone(), active.clone());
    let tcp_task = tokio::spawn(async move {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                result=tcp.accept()=>{let (mut stream,_)=result.unwrap();let count=count.clone();let active=connections.clone();
                    clients.spawn(async move {
                        active.fetch_add(1,Ordering::SeqCst);let _guard=Active(active);
                        let n=stream.read_u16().await.unwrap() as usize;let mut buffer=vec![0;n];
                        stream.read_exact(&mut buffer).await.unwrap();let ordinal=count.fetch_add(1,Ordering::SeqCst);
                        if matches!(behavior,Behavior::Stall) {let _=stream.read(&mut [0;1]).await; return;}
                        let bytes=reply(&buffer,behavior,true,ordinal);
                        stream.write_u16(bytes.len() as u16).await.unwrap();let _=stream.write_all(&bytes).await;
                    });
                },
                _=clients.join_next(),if !clients.is_empty()=>{}
            }
        }
    });
    let count = requests.clone();
    let observed_names = names.clone();
    let udp_task = tokio::spawn(async move {
        let mut buffer = vec![0; 65535];
        let mut pending = JoinSet::new();
        loop {
            tokio::select! {
                result=udp.recv_from(&mut buffer)=>{
                    let (n,peer)=result.unwrap();let ordinal=count.fetch_add(1,Ordering::SeqCst);
                    if let Ok(message)=Message::from_vec(&buffer[..n]) {
                        let mut names=observed_names.lock().unwrap();
                        assert!(names.len()<128);names.insert(message.queries[0].name().to_ascii());
                    }
                    if matches!(behavior,Behavior::Stall) {continue;}
                    let bytes=reply(&buffer[..n],behavior,false,ordinal);let socket=udp.clone();
                    pending.spawn(async move {if (matches!(behavior,Behavior::Late) && ordinal==0) || (matches!(behavior,Behavior::Switch) && ordinal==9) {sleep(Duration::from_millis(150)).await;}
                        let _=socket.send_to(&bytes,peer).await;});
                },
                _=pending.join_next(),if !pending.is_empty()=>{}
            }
        }
    });
    Fixture {
        peer,
        tasks: vec![tcp_task, udp_task],
        requests,
        active,
        names,
    }
}
#[test]
fn maximum_accepted_run_keeps_slot_arithmetic_in_range() {
    let dir = tempfile::tempdir().unwrap();
    let mut r = record(dir.path(), &["127.0.0.1:9999".parse().unwrap()]);
    r.mode = soak_record::Mode::Soak;
    r.phases[0].seconds = 259200;
    r.phases[0].qps = 100000;
    let _ = prepare(&r);
    assert_eq!(
        slot_offset(25_920_000_000 - 1, 100000),
        Duration::from_secs(259200) - Duration::from_micros(10)
    );
}
#[test]
fn strict_record_rejects_missing_unsafe_and_unbounded_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let r = record(dir.path(), &["127.0.0.1:9999".parse().unwrap()]);
    for (key, value) in [
        ("/limits/latency_us", json!(0)),
        ("/limits/outstanding", json!(257)),
        ("/limits/artifact_bytes", json!(134217729)),
        ("/phases/0/deadline_ms", json!(2001)),
        ("/phases/0/qps", json!(0)),
        ("/phases/0/seconds", json!(901)),
        ("/phases/0/accepted", json!([4])),
        ("/lanes/0/endpoint", json!("8.8.8.8:53")),
        ("/clients/0/bind", json!("0.0.0.0")),
        ("/authority/instruction", json!("")),
        ("/identity/source_sha256", json!("missing")),
        ("/collector/path", json!("relative")),
        ("/lanes/0/responses", json!(["ff"])),
        ("/external_checks", json!([])),
    ] {
        let mut v = serde_json::to_value(&r).unwrap();
        *v.pointer_mut(key).unwrap() = value;
        assert!(
            Prepared::parse(serde_json::to_vec(&v).unwrap()).is_err(),
            "{key}"
        );
    }
    let mut v = serde_json::to_value(&r).unwrap();
    v["unknown"] = json!(true);
    assert!(Prepared::parse(serde_json::to_vec(&v).unwrap()).is_err());
    assert!(Prepared::parse(vec![b' '; 256 * 1024 + 1]).is_err());
    let mut r = r;
    r.lanes[0].responses = vec![hex(&Message::query())];
    assert!(Prepared::parse(serde_json::to_vec(&r).unwrap()).is_err());
}
#[test]
fn oracle_checks_headers_all_sections_rrsets_ttl_and_edns() {
    let mut expected = answer();
    expected.add_answer(expected.answers[0].clone());
    let request = expected.clone();
    for mutation in 0..10 {
        let mut actual = expected.clone();
        match mutation {
            0 => actual.metadata.id += 1,
            1 => actual.metadata.recursion_available = false,
            2 => actual.queries.clear(),
            3 => actual.answers[0].name = Name::from_ascii("wrong.test.").unwrap(),
            4 => actual.answers[0].data = RData::A(A::new(192, 0, 2, 2)),
            5 => actual.answers[0].ttl = 61,
            6 => actual.additionals.push(actual.answers[0].clone()),
            7 => actual.authorities.push(actual.answers[0].clone()),
            8 => actual.edns = Some(Default::default()),
            _ => actual.answers.clear(),
        }
        assert!(
            !soak_probe::valid(&request, &actual, &expected, 0, false),
            "mutation {mutation}"
        );
    }
    let mut actual = expected.clone();
    actual.answers.reverse();
    actual.answers[0].ttl = 0;
    assert!(soak_probe::valid(&request, &actual, &expected, 0, false));
    assert!(!soak_probe::valid(&request, &actual, &expected, 1, false));
}
#[test]
fn samples_preserve_resets_and_reject_bad_freshness_identity_schema_and_limits() {
    let dir = tempfile::tempdir().unwrap();
    let r = record(dir.path(), &["127.0.0.1:9999".parse().unwrap()]);
    let first = sample(&r, 1, 100);
    let mut next = sample(&r, 2, 105);
    next.unix_ms = first.unix_ms;
    let mut s = Summary::default();
    s.record(None, first.clone()).unwrap();
    s.record(Some(&first), next.clone()).unwrap();
    assert_eq!(s.counter_deltas["requests"], 5);
    let mut reset = next.clone();
    reset.sequence = 3;
    reset.process_id = "124:789".into();
    reset.counters.insert("requests".into(), 2);
    s.record(Some(&next), reset.clone()).unwrap();
    assert_eq!(s.counter_deltas["requests"], 5);
    assert_eq!(s.counter_resets, 1);
    assert_eq!(s.resets[0].from_process, "123:456");
    assert_eq!(s.resets[0].to_process, "124:789");
    for mutation in 0..6 {
        let mut bad = first.clone();
        match mutation {
            0 => bad.unix_ms = 0,
            1 => bad.target_id = "other".into(),
            2 => bad.resources[0] = u64::MAX,
            3 => bad.generation = 9,
            4 => bad.counters.clear(),
            _ => bad.unix_ms += 10000,
        }
        assert!(bad.validate(&r, &r.phases[0], now_ms().unwrap()).is_err());
    }
    next.sequence = 0;
    assert!(soak_samples::continuity(&first, &next).is_err());
    next = first.clone();
    next.counters.insert("requests".into(), 101);
    assert!(soak_samples::continuity(&first, &next).is_err());
    for _ in 0..15 {
        s.record(Some(&next), reset.clone()).unwrap();
    }
    assert!(s.record(Some(&next), reset).is_err());
}
#[tokio::test]
async fn udp_and_tcp_independent_endpoints_keep_target_alive_and_merge_counts() {
    let (a, b) = (fixture(Behavior::Good).await, fixture(Behavior::Good).await);
    let dir = tempfile::tempdir().unwrap();
    let r = record(dir.path(), &[a.peer, b.peer]);
    let _collector = collector(&r, a.requests.clone());
    let output = dir.path().join("pass");
    let report = drive(prepare(&r), &output, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(report["driver_passed"], true, "{report}");
    assert_eq!(report["counts"]["sent"], 10);
    assert_eq!(a.requests.load(Ordering::SeqCst), 5);
    assert_eq!(b.requests.load(Ordering::SeqCst), 5);
    let aggregate: Value =
        serde_json::from_slice(&std::fs::read(output.join("aggregate.json")).unwrap()).unwrap();
    for lane in aggregate["lanes"].as_array().unwrap() {
        assert_eq!(
            lane["histogram"]["bins"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap())
                .sum::<u64>(),
            5
        );
    }
    assert!(
        drive(prepare(&r), &output, CancellationToken::new())
            .await
            .is_err()
    );
    assert!(matches!(
        soak_probe::probe(
            r.clients[0].bind,
            r.lanes[0].clone(),
            vec![answer()],
            vec![0],
            99,
            500,
            42
        )
        .await,
        Outcome::Reply { wrong: false, .. }
    ));
}
#[tokio::test]
async fn fresh_names_and_phase_oracles_do_not_reset_the_target_or_aggregate() {
    let f = fixture(Behavior::Switch).await;
    let dir = tempfile::tempdir().unwrap();
    let mut r = record(dir.path(), &[f.peer]);
    r.lanes[0].fresh = true;
    let mut changed = answer();
    changed.answers[0].data = RData::A(A::new(192, 0, 2, 9));
    r.lanes[0].responses.push(hex(&changed));
    let mut phase = r.phases[0].clone();
    phase.id = "changed".into();
    phase.accepted = vec![1];
    r.phases.push(phase);
    let _collector = collector(&r, f.requests.clone());
    let output = dir.path().join("phases");
    let report = drive(prepare(&r), &output, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(report["driver_passed"], true, "{report}");
    assert_eq!(report["counts"]["replies"], 20);
    assert_eq!(report["windows"], 2);
    assert_eq!(f.requests.load(Ordering::SeqCst), 20);
    let names = f.names.lock().unwrap();
    assert_eq!(names.len(), 20);
    assert!(names.iter().all(|n| n.starts_with("q-000000000000002a-")));
    drop(names);
    let windows = std::fs::read_to_string(output.join("windows.ndjson")).unwrap();
    let rows: Vec<Value> = windows
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows[0]["phase"], "steady");
    assert_eq!(rows[1]["phase"], "changed");
    assert_eq!(rows[0]["inflight_end"], 1);
    assert_eq!(rows[1]["inflight_start"], 1);
    assert_eq!(rows[1]["completed_phase_counts"]["steady"], 1);
    assert_eq!(rows[1]["completed_phase_counts"]["changed"], 10);
    assert_eq!(
        rows[1]["offer_start_ms"].as_u64().unwrap() - rows[0]["offer_start_ms"].as_u64().unwrap(),
        1000
    );
    let aggregate: Value =
        serde_json::from_slice(&std::fs::read(output.join("aggregate.json")).unwrap()).unwrap();
    assert_eq!(aggregate["lanes"][0]["histogram"]["replies"], 20);
}
#[tokio::test]
async fn wrong_and_malformed_replies_stop_with_preserved_failure_evidence() {
    for behavior in [Behavior::Wrong, Behavior::Malformed] {
        let f = fixture(behavior).await;
        let dir = tempfile::tempdir().unwrap();
        let r = record(dir.path(), &[f.peer]);
        let _collector = collector(&r, f.requests.clone());
        let output = dir.path().join("failed");
        let report = drive(prepare(&r), &output, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(report["driver_passed"], false);
        assert_eq!(report["counts"]["wrong"], 1);
        assert_eq!(report["accounting_reconciled"], true);
        assert!(output.join("aggregate.json").exists());
        assert!(report["failure"].as_str().unwrap().contains("wrong_answer"));
    }
}
#[tokio::test]
async fn truncation_fallback_and_timeout_socket_retirement() {
    let f = fixture(Behavior::Truncate).await;
    let dir = tempfile::tempdir().unwrap();
    let mut r = record(dir.path(), &[f.peer]);
    r.lanes[0].tcp_fallback = true;
    assert!(matches!(
        soak_probe::probe(
            r.clients[0].bind,
            r.lanes[0].clone(),
            vec![answer()],
            vec![0],
            10,
            500,
            42
        )
        .await,
        Outcome::Reply { wrong: false, .. }
    ));
    assert_eq!(f.requests.load(Ordering::SeqCst), 2);
    let late = fixture(Behavior::Late).await;
    r.lanes[0].endpoint = late.peer;
    r.lanes[0].tcp_fallback = false;
    assert_eq!(
        soak_probe::probe(
            r.clients[0].bind,
            r.lanes[0].clone(),
            vec![answer()],
            vec![0],
            10,
            20,
            42
        )
        .await,
        Outcome::Timeout
    );
    sleep(Duration::from_millis(160)).await;
    assert!(matches!(
        soak_probe::probe(
            r.clients[0].bind,
            r.lanes[0].clone(),
            vec![answer()],
            vec![0],
            10,
            500,
            42
        )
        .await,
        Outcome::Reply { wrong: false, .. }
    ));
}
#[tokio::test]
async fn overload_is_explicit_and_cancellation_closes_owned_tcp_connections() {
    for cancel_run in [false, true] {
        let f = fixture(Behavior::Stall).await;
        let dir = tempfile::tempdir().unwrap();
        let mut r = record(dir.path(), &[f.peer]);
        r.lanes[0].transport = Transport::Tcp;
        r.limits.outstanding = 1;
        r.phases[0].seconds = 5;
        r.phases[0].deadline_ms = 2000;
        r.limits.latency_us = 2_000_000;
        let _collector = collector(&r, f.requests.clone());
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let observed = f.requests.clone();
        let active = f.active.clone();
        let task = tokio::spawn(async move {
            if cancel_run {
                timeout(Duration::from_secs(1), async {
                    while observed.load(Ordering::SeqCst) == 0 || active.load(Ordering::SeqCst) == 0
                    {
                        sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
                trigger.cancel();
            }
        });
        let report = drive(prepare(&r), &dir.path().join("failed"), cancel)
            .await
            .unwrap();
        task.await.unwrap();
        assert_eq!(report["driver_passed"], false);
        assert_eq!(report["accounting_reconciled"], true);
        assert_eq!(report["counts"]["cancelled"], 1);
        if cancel_run {
            assert_eq!(report["failure"], "cancelled");
        } else {
            assert!(report["counts"]["skipped"].as_u64().unwrap() > 0);
        }
        timeout(Duration::from_secs(1), async {
            while f.active.load(Ordering::SeqCst) != 0 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}
#[tokio::test]
async fn nominal_timeouts_missing_samples_and_empty_evidence_fail() {
    let f = fixture(Behavior::Stall).await;
    let dir = tempfile::tempdir().unwrap();
    let mut r = record(dir.path(), &[f.peer]);
    r.phases[0].deadline_ms = 20;
    r.limits.latency_us = 20000;
    let _collector = collector(&r, f.requests.clone());
    let report = drive(
        prepare(&r),
        &dir.path().join("timeout"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(
        report["failure"]
            .as_str()
            .unwrap()
            .contains("unexpected_timeout")
    );
    assert_eq!(report["counts"]["timeouts"], 1);
    drop(_collector);
    std::fs::remove_file(&r.collector.path).unwrap();
    let report = drive(
        prepare(&r),
        &dir.path().join("missing"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report["driver_passed"], false);
    assert_eq!(report["counts"]["sent"], 0);
    assert_eq!(report["resources"]["samples"], 0);
}
#[test]
fn recorder_enforces_clipping_window_aggregate_and_total_caps() {
    let dir = tempfile::tempdir().unwrap();
    let mut r = record(dir.path(), &["127.0.0.1:9999".parse().unwrap()]);
    let raw = serde_json::to_vec(&r).unwrap();
    let mut recorder = Recorder::new(&r, &raw, &dir.path().join("clipped")).unwrap();
    recorder.sent(0);
    assert_eq!(
        recorder.outcome(
            0,
            Outcome::Reply {
                us: 2_000_001,
                wrong: false
            },
            &r.phases[0]
        ),
        Some("clipped_latency")
    );
    let report = recorder
        .finish(&r.phases[0], 1, Some("clipped_latency".into()), false)
        .unwrap();
    assert_eq!(report["driver_passed"], false);
    r.limits.window_bytes = 1024;
    let mut large = sample(&r, 0, 0);
    large.counters = (0..16)
        .map(|i| (format!("counter_{i:02}_{}", "x".repeat(40)), 0))
        .collect();
    write_sample(&r, &large);
    let mut recorder = Recorder::new(&r, &raw, &dir.path().join("window")).unwrap();
    recorder.sample(&r.phases[0]).unwrap();
    recorder.sent(0);
    recorder.outcome(
        0,
        Outcome::Reply {
            us: 1,
            wrong: false,
        },
        &r.phases[0],
    );
    let report = recorder.finish(&r.phases[0], 1, None, true).unwrap();
    assert!(
        report["failure"]
            .as_str()
            .unwrap()
            .contains("window record limit")
    );
    r.limits.window_bytes = 16384;
    r.limits.aggregate_bytes = 256 * 1024;
    r.limits.artifact_bytes = 768 * 1024;
    let mut recorder = Recorder::new(&r, &raw, &dir.path().join("total")).unwrap();
    let mut failed = false;
    for i in 0..4320 {
        if let Err(e) = recorder.flush(&r.phases[0], i * 60000, &[0]) {
            assert!(e.to_string().contains("artifact limit"));
            failed = true;
            break;
        }
    }
    assert!(failed);
    let report = recorder
        .finish(&r.phases[0], 1, Some("artifact limit".into()), false)
        .unwrap();
    assert_eq!(report["driver_passed"], false);
    r.lanes = (0..8)
        .map(|i| {
            let mut lane = r.lanes[0].clone();
            lane.id = format!("l{i}");
            lane
        })
        .collect();
    let recorder = Recorder::new(&r, &raw, &dir.path().join("aggregate")).unwrap();
    let report = recorder.finish(&r.phases[0], 1, None, false).unwrap();
    assert!(
        report["failure"]
            .as_str()
            .unwrap()
            .contains("final evidence limit")
    );
    assert!(dir.path().join("aggregate/summary.json").exists());
}

#[path = "soak_envelope_tests.rs"]
mod envelope;
