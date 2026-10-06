//! Independently usable matching and forwarding components.
#[cfg(test)]
mod tests {
    use rustwalld_dns_filter::{Action, FilterSnapshot, ListInput};
    #[test]
    fn filtering_needs_no_daemon_or_runtime() {
        let filters = FilterSnapshot::compile(
            &[
                ListInput {
                    name: "blocked".into(),
                    action: Action::Block,
                    rules: "ads.test\n=exact.test".into(),
                },
                ListInput {
                    name: "allowed".into(),
                    action: Action::Allow,
                    rules: "=safe.ads.test".into(),
                },
            ],
            100,
            4096,
        )
        .unwrap();
        assert_eq!(filters.evaluate("child.ads.test").action, Action::Block);
        assert_eq!(filters.evaluate("safe.ads.test").action, Action::Allow);
        assert_eq!(filters.evaluate("child.exact.test").action, Action::Allow);
    }
    #[cfg(feature = "parallel")]
    #[test]
    fn explicitly_owned_pool_compiles_without_a_daemon_or_global_pool() {
        let compiler = rustwalld_dns_filter::ParallelCompiler::new(2).unwrap();
        let rules = (0..40000).map(|i| format!("=rule{i}.test\n")).collect();
        let snapshot = compiler
            .compile(
                &[ListInput {
                    name: "large".into(),
                    action: Action::Block,
                    rules,
                }],
                40000,
                1024 * 1024,
            )
            .unwrap();
        assert_eq!(snapshot.effective_rules(), 40000);
        assert_eq!(snapshot.evaluate("rule39999.test").action, Action::Block);
        assert_eq!(
            snapshot.evaluate("child.rule39999.test").action,
            Action::Allow
        );
    }
    #[tokio::test]
    async fn resolver_accepts_an_explicit_local_endpoint() {
        use hickory_proto::{
            op::{Message, Metadata, Query, ResponseCode},
            rr::{Name, RecordType},
        };
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.metadata = Metadata::response_from_request(&request.metadata);
            response.metadata.recursion_available = true;
            response.metadata.response_code = ResponseCode::NXDomain;
            response.queries = request.queries.clone();
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let resolver = rustwalld_dns_resolver::Forwarder::new(
            vec![address],
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        assert_eq!(
            resolver
                .resolve(&query)
                .await
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
        mock.await.unwrap();
    }
}
