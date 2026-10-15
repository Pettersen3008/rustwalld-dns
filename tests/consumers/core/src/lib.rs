//! This crate deliberately builds outside the library workspace, using public APIs only.
#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message, Query, ResponseCode},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };
    use rustwalld_dns_core::{
        Action, Engine, EngineConfig, ListInput, PolicyConfigSet, PolicySnapshot, PublicationError,
        PublicationTarget, Server, ServerConfig, Telemetry, reply,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;
    fn query(domain: &str, id: u16) -> Message {
        let mut query = Message::query();
        query.metadata.id = id;
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
        ));
        query
    }
    async fn exchange(address: std::net::SocketAddr, query: Message) -> Message {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&query.to_vec().unwrap(), address)
            .await
            .unwrap();
        let mut buffer = [0; 1232];
        let len = timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        Message::from_vec(&buffer[..len]).unwrap()
    }
    #[tokio::test]
    async fn public_api_preserves_dns_reload_events_and_independent_lifecycles() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counts = hits.clone();
        let mock_stop = CancellationToken::new();
        let mock_cancel = mock_stop.clone();
        let mock = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let packet = tokio::select! {_=mock_cancel.cancelled()=>break,result=upstream.recv_from(&mut buffer)=>result.unwrap()};
                let request = Message::from_vec(&buffer[..packet.0]).unwrap();
                let mut response = reply(&request, ResponseCode::NoError);
                response.add_answer(Record::from_rdata(
                    request.queries[0].name().clone(),
                    60,
                    RData::A(A("192.0.2.7".parse().unwrap())),
                ));
                counts.fetch_add(1, Ordering::Relaxed);
                upstream
                    .send_to(&response.to_vec().unwrap(), packet.1)
                    .await
                    .unwrap();
            }
        });
        let mut config = PolicyConfigSet::default();
        config.upstreams[0].addresses = vec![upstream_address];
        config.policies[0].lists = vec![
            ListInput {
                syntax: Default::default(),
                name: "blocks".into(),
                action: Action::Block,
                rules: "ads.test".into(),
            },
            ListInput {
                syntax: Default::default(),
                name: "allows".into(),
                action: Action::Allow,
                rules: "=safe.ads.test".into(),
            },
        ];
        let (telemetry, mut events) = Telemetry::channel(16);
        let initial = config.clone();
        let snapshot = tokio::task::spawn_blocking(move || PolicySnapshot::compile(initial, 1))
            .await
            .unwrap()
            .unwrap();
        let (engine, control) = Engine::controlled(snapshot, EngineConfig::default(), telemetry);
        let engine = Arc::new(engine);
        let server = Server::bind(
            ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            engine.clone(),
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let stop = CancellationToken::new();
        let serving = tokio::spawn(server.run(stop.clone()));
        assert_eq!(
            exchange(address, query("ads.test", 41))
                .await
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
        let allowed = exchange(address, query("safe.ads.test", 42)).await;
        assert_eq!(allowed.answers.len(), 1);
        assert_eq!(allowed.metadata.id, 42);
        let mut tcp = TcpStream::connect(address).await.unwrap();
        let bytes = query("SAFE.ads.test", 55).to_vec().unwrap();
        tcp.write_u16(bytes.len() as u16).await.unwrap();
        tcp.write_all(&bytes).await.unwrap();
        let len = timeout(Duration::from_secs(2), tcp.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = vec![0; len as usize];
        tcp.read_exact(&mut bytes).await.unwrap();
        let cached = Message::from_vec(&bytes).unwrap();
        assert_eq!(cached.metadata.id, 55);
        assert_eq!(cached.answers.len(), 1);
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        let original = control.version();
        config.policies[0].lists.clear();
        let shadow_config = config.clone();
        let shadow = tokio::task::spawn_blocking(move || PolicySnapshot::compile(shadow_config, 2))
            .await
            .unwrap()
            .unwrap();
        control
            .prepare(shadow, PublicationTarget::Shadow, original)
            .unwrap()
            .commit();
        assert_eq!(
            exchange(address, query("ads.test", 56))
                .await
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
        let mut difference = false;
        while let Ok(event) = events.try_recv() {
            difference |= event.shadow.is_some_and(|s| s.differs);
        }
        assert!(difference);
        let active_config = config.clone();
        let active = tokio::task::spawn_blocking(move || PolicySnapshot::compile(active_config, 3))
            .await
            .unwrap()
            .unwrap();
        control
            .prepare(active, PublicationTarget::Active, control.version())
            .unwrap()
            .commit();
        assert_eq!(
            exchange(address, query("ads.test", 57)).await.answers.len(),
            1
        );
        let stale = PolicySnapshot::compile(config.clone(), 4).unwrap();
        assert!(matches!(
            control.prepare(stale, PublicationTarget::Active, original),
            Err(PublicationError::Stale)
        ));
        let (telemetry, _) = Telemetry::channel(1);
        let other = Arc::new(Engine::with_config(
            PolicySnapshot::compile(config, 1).unwrap(),
            EngineConfig::default(),
            telemetry,
        ));
        let server = Server::bind(
            ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            other,
        )
        .await
        .unwrap();
        let other_address = server.local_addr().unwrap();
        let other_stop = CancellationToken::new();
        let other_serving = tokio::spawn(server.run(other_stop.clone()));
        stop.cancel();
        timeout(Duration::from_secs(6), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            exchange(other_address, query("other.test", 58))
                .await
                .answers
                .len(),
            1
        );
        other_stop.cancel();
        other_serving.await.unwrap().unwrap();
        mock_stop.cancel();
        mock.await.unwrap();
    }
}
