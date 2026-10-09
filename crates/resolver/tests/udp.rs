#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use rustwalld_dns_resolver::Forwarder;
use std::{net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

fn request() -> Message {
    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("large.test.").unwrap(),
        RecordType::A,
    ));
    request
}
fn response(request: &Message, answers: u8) -> Message {
    let mut response = request.clone().into_response();
    for index in 0..answers {
        response.add_answer(Record::from_rdata(
            request.queries[0].name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, index))),
        ));
    }
    response
}

#[tokio::test]
async fn oversized_udp_reply_retries_tcp_with_one_framed_write() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(address).await.unwrap();
    let udp_task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (len, source) = udp.recv_from(&mut bytes).await.unwrap();
        let request = Message::from_vec(&bytes[..len]).unwrap();
        assert!(request.edns.is_none());
        // Without EDNS the limit is 512 bytes; 40 answers exceed it with TC clear.
        let oversized = response(&request, 40).to_vec().unwrap();
        assert!(oversized.len() > 512);
        udp.send_to(&oversized, source).await.unwrap();
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        // The length prefix and message arrive together in a single segment.
        let mut frame = [0; 4096];
        let read = stream.read(&mut frame).await.unwrap();
        let len = usize::from(u16::from_be_bytes([frame[0], frame[1]]));
        assert_eq!(read, len + 2, "TCP request was split across writes");
        let request = Message::from_vec(&frame[2..read]).unwrap();
        let bytes = response(&request, 1).to_vec().unwrap();
        stream
            .write_all(&u16::try_from(bytes.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let forwarder = Forwarder::new(vec![address], Duration::from_secs(2)).unwrap();
    let resolved = forwarder.resolve(&request()).await.unwrap();
    assert_eq!(resolved.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resolved.answers.len(), 1);
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
}
