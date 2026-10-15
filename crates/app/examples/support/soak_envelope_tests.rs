//! Regressions for the frozen request envelope and complete packet boundaries.
use super::*;
use tokio::sync::mpsc;

async fn cd_exchange(transport: Transport, fallback: bool, cd: bool, wrong: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(endpoint).await.unwrap();
    let (observed, mut observations) = mpsc::channel::<Message>(2);
    let tcp_observed = observed.clone();
    let udp_task = tokio::spawn(async move {
        if transport == Transport::Udp {
            timeout(Duration::from_secs(2), async {
                let mut bytes = [0; 4096];
                let (n, peer) = udp.recv_from(&mut bytes).await.unwrap();
                let query = Message::from_vec(&bytes[..n]).unwrap();
                observed.send(query.clone()).await.unwrap();
                let mut response = answer();
                response.metadata.id = query.metadata.id;
                response.metadata.checking_disabled = query.metadata.checking_disabled ^ wrong;
                if fallback {
                    response.metadata.truncation = true;
                    response.answers.clear();
                }
                udp.send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            })
            .await
            .unwrap();
        }
    });
    let tcp_task = tokio::spawn(async move {
        if transport == Transport::Tcp || (fallback && !wrong) {
            timeout(Duration::from_secs(2), async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let size = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).await.unwrap();
                let query = Message::from_vec(&bytes).unwrap();
                tcp_observed.send(query.clone()).await.unwrap();
                let mut response = answer();
                response.metadata.id = query.metadata.id;
                response.metadata.checking_disabled = query.metadata.checking_disabled ^ wrong;
                let bytes = response.to_vec().unwrap();
                stream.write_u16(bytes.len() as u16).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
            })
            .await
            .unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let mut run = record(dir.path(), &[endpoint]);
    run.lanes[0].transport = transport;
    run.lanes[0].tcp_fallback = fallback;
    let mut reference = answer();
    reference.metadata.checking_disabled = cd;
    run.lanes[0].responses[0] = hex(&reference);
    let prepared = prepare(&run);
    let outcome = soak_probe::probe(
        run.clients[0].bind,
        run.lanes[0].clone(),
        prepared.templates[0].clone(),
        vec![0],
        42,
        500,
        7,
    )
    .await;
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
    assert!(
        matches!(outcome, Outcome::Reply { wrong: found, .. } if found == wrong),
        "{outcome:?}"
    );
    let mut count = 0;
    while let Some(query) = observations.recv().await {
        count += 1;
        assert_eq!(query.metadata.checking_disabled, cd);
        assert!(query.metadata.recursion_desired);
        assert_eq!(
            query.metadata.message_type,
            hickory_proto::op::MessageType::Query
        );
        assert!(!query.metadata.recursion_available && !query.metadata.authentic_data);
        assert!(
            query.answers.is_empty()
                && query.authorities.is_empty()
                && query.additionals.is_empty()
        );
    }
    assert_eq!(count, if fallback && !wrong { 2 } else { 1 });
}

#[tokio::test]
async fn frozen_cd_survives_udp_tcp_and_fallback_and_wrong_cd_is_rejected() {
    for cd in [false, true] {
        for (transport, fallback) in [
            (Transport::Udp, false),
            (Transport::Tcp, false),
            (Transport::Udp, true),
        ] {
            for wrong in [false, true] {
                cd_exchange(transport, fallback, cd, wrong).await;
            }
        }
    }
}

#[test]
fn mixed_cd_references_are_rejected_before_networking() {
    let dir = tempfile::tempdir().unwrap();
    let mut run = record(dir.path(), &["127.0.0.1:9999".parse().unwrap()]);
    let mut reference = answer();
    reference.metadata.checking_disabled = true;
    run.lanes[0].responses.push(hex(&reference));
    assert!(Prepared::parse(serde_json::to_vec(&run).unwrap()).is_err());
}

#[test]
fn reference_decoder_rejects_suffix_truncation_and_reserved_header_bit() {
    let valid = answer().to_vec().unwrap();
    let encode = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert!(soak_record::decode(&encode(&valid)).is_ok());
    let mut trailing = valid.clone();
    trailing.extend_from_slice(b"unparsed suffix");
    let mut reserved = valid.clone();
    reserved[3] |= 0x40;
    for wire in [&trailing[..], &reserved[..], &valid[..valid.len() - 1]] {
        assert!(soak_record::decode(&encode(wire)).is_err());
    }
}

#[tokio::test]
async fn udp_and_tcp_oracles_reject_trailing_and_reserved_wire() {
    for behavior in [Behavior::Trailing, Behavior::Reserved] {
        let f = fixture(behavior).await;
        let dir = tempfile::tempdir().unwrap();
        let mut run = record(dir.path(), &[f.peer]);
        for transport in [Transport::Udp, Transport::Tcp] {
            run.lanes[0].transport = transport;
            assert!(matches!(
                soak_probe::probe(
                    run.clients[0].bind,
                    run.lanes[0].clone(),
                    vec![answer()],
                    vec![0],
                    42,
                    500,
                    7
                )
                .await,
                Outcome::Reply { wrong: true, .. }
            ));
        }
    }
}

#[tokio::test]
async fn matching_oversized_udp_is_wrong_but_complete_tcp_is_valid() {
    let f = fixture(Behavior::Oversized).await;
    let dir = tempfile::tempdir().unwrap();
    let mut run = record(dir.path(), &[f.peer]);
    let mut large = answer();
    for last in 2..=64 {
        large.add_answer(Record::from_rdata(
            large.queries[0].name().clone(),
            60,
            RData::A(A::new(192, 0, 2, last)),
        ));
    }
    assert!(large.to_vec().unwrap().len() > 512);
    run.lanes[0].responses[0] = hex(&large);
    let prepared = prepare(&run);
    for transport in [Transport::Udp, Transport::Tcp] {
        run.lanes[0].transport = transport;
        let outcome = soak_probe::probe(
            run.clients[0].bind,
            run.lanes[0].clone(),
            prepared.templates[0].clone(),
            vec![0],
            42,
            500,
            7,
        )
        .await;
        assert!(
            matches!(outcome, Outcome::Reply { wrong, .. } if wrong == (transport == Transport::Udp)),
            "{outcome:?}"
        );
    }
}
