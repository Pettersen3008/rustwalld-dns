#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn udp_tcp_records_and_persistent_tcp() {
    let mock = Mock::start(false, false).await;
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    for kind in [RecordType::A, RecordType::AAAA, RecordType::CNAME] {
        let request = query(kind);
        let result = udp_query(addr, &request).await;
        assert_eq!(result.metadata.id, 42);
        assert_eq!(result.answers[0].data.record_type(), kind);
    }
    let mut stream = TcpStream::connect(addr).await.unwrap();
    for kind in [RecordType::A, RecordType::AAAA] {
        let bytes = query(kind).to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut bytes = vec![0; len];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(
            Message::from_vec(&bytes).unwrap().answers[0]
                .data
                .record_type(),
            kind
        );
    }
    cancel.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn spoofed_responses_ignored_and_truncation_retried_tcp() {
    let mock = Mock::start(true, true).await;
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    let response = udp_query(addr, &query(RecordType::A)).await;
    assert!(!response.metadata.truncation);
    assert_eq!(response.answers.len(), 1);
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn timeout_fallback_and_servfail() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mock = Mock::start(false, false).await;
    let (addr, cancel, task) = server(vec![silent.local_addr().unwrap(), mock.addr]).await;
    assert_eq!(
        udp_query(addr, &query(RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
    let (addr, cancel, task) = server(vec![silent.local_addr().unwrap()]).await;
    assert_eq!(
        udp_query(addr, &query(RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn malformed_dropped_invalid_queries_never_forwarded() {
    let mock = Mock::start(false, false).await;
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Compression pointer points to itself.
    let mut malformed = vec![0, 42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1];
    for bytes in [&[][..], &malformed[..], &[0; 11][..]] {
        socket.send_to(bytes, addr).await.unwrap();
        assert!(
            timeout(Duration::from_millis(20), socket.recv(&mut [0; 512]))
                .await
                .is_err()
        );
    }
    malformed.clear();
    let mut request = query(RecordType::A);
    request.add_query(request.queries[0].clone());
    assert_eq!(
        udp_query(addr, &request).await.metadata.response_code,
        ResponseCode::FormErr
    );
    request = query(RecordType::AXFR);
    assert_eq!(
        udp_query(addr, &request).await.metadata.response_code,
        ResponseCode::Refused
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 0);
    assert_eq!(
        udp_query(addr, &query(RecordType::A)).await.answers.len(),
        1
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn udp_size_limit_edns_and_tcp_idle_shutdown() {
    let mock = Mock::start(false, false).await;
    let (engine, _receiver) = engine_for(&mock, 1000, 32);
    let mut config = engine.active.load().config().clone();
    config.policies[0]
        .rewrites
        .push(rustwalld_dns_policy::Rewrite {
            domain: "test.example".into(),
            addresses: (1..=32)
                .map(|i| format!("2001:db8::{i}").parse().unwrap())
                .collect(),
            ttl: 60,
        });
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 2).unwrap()));
    let client = "127.0.0.1".parse().unwrap();
    let request = query(RecordType::AAAA);
    let bytes = engine
        .answer(&request.to_vec().unwrap(), client, false)
        .await
        .unwrap();
    assert!(bytes.len() <= 512);
    assert!(Message::from_vec(&bytes).unwrap().metadata.truncation);
    let mut request = request;
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    request.edns = Some(edns);
    let bytes = engine
        .answer(&request.to_vec().unwrap(), client, false)
        .await
        .unwrap();
    assert!(!Message::from_vec(&bytes).unwrap().metadata.truncation);
    request.edns.as_mut().unwrap().set_version(1);
    // BADVERS and BADSIG share wire RCODE 16; Hickory decodes it as BADSIG.
    let reply = Message::from_vec(
        &engine
            .answer(&request.to_vec().unwrap(), client, false)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(u16::from(reply.metadata.response_code), 16);
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    let _idle = TcpStream::connect(addr).await.unwrap();
    cancel.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn escaped_dot_in_dns_label_does_not_false_block_suffix() {
    let mock = Mock::start(false, false).await;
    let (engine, _receiver) = engine_for(&mock, 100, 32);
    let mut config = engine.active.load().config().clone();
    config.policies[0]
        .lists
        .push(rustwalld_dns_filter::ListInput {
            name: "deny".into(),
            action: rustwalld_dns_filter::Action::Block,
            rules: "example.com".into(),
        });
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 2).unwrap()));
    let mut request = query(RecordType::A);
    request.queries[0].set_name(Name::from_ascii(r"evil\.example.com.").unwrap());
    let response = engine
        .answer(
            &request.to_vec().unwrap(),
            "127.0.0.1".parse().unwrap(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        Message::from_vec(&response).unwrap().metadata.response_code,
        ResponseCode::NoError
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    request.queries[0].set_name(Name::from_ascii(r"evil\.label.example.com.").unwrap());
    let response = engine
        .answer(
            &request.to_vec().unwrap(),
            "127.0.0.1".parse().unwrap(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        Message::from_vec(&response).unwrap().metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
}
