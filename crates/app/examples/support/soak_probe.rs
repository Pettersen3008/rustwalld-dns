//! One bounded exchange owns its sockets. No retry or connection survives a timeout.
use super::soak_record::{Lane, Transport, complete_message, invalid};
use hickory_proto::{op::Message, rr::Record};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
};

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Reply { us: u64, wrong: bool },
    Timeout,
    Error,
}

fn records(actual: &[Record], expected: &[Record], floor: u32, partial: bool) -> bool {
    if (!partial && actual.len() != expected.len()) || actual.len() > expected.len() {
        return false;
    }
    // Compare as a multiset: wire RR ordering is not an RRset contract.
    let mut used = vec![false; expected.len()];
    actual.iter().all(|a| {
        let found = expected.iter().enumerate().position(|(i, e)| {
            !used[i]
                && a.name == e.name
                && a.dns_class == e.dns_class
                && a.data == e.data
                && a.ttl >= floor
                && a.ttl <= e.ttl
        });
        if let Some(i) = found {
            used[i] = true;
            true
        } else {
            false
        }
    })
}
pub fn valid(
    request: &Message,
    actual: &Message,
    expected: &Message,
    floor: u32,
    partial: bool,
) -> bool {
    let mut metadata = expected.metadata;
    metadata.id = request.metadata.id;
    metadata.truncation = partial;
    actual.metadata == metadata
        && actual.queries == request.queries
        && actual.edns == expected.edns
        && actual.signature == expected.signature
        && records(&actual.answers, &expected.answers, floor, partial)
        && records(&actual.authorities, &expected.authorities, floor, partial)
        && records(&actual.additionals, &expected.additionals, floor, partial)
}
async fn exchange(
    bind: IpAddr,
    peer: SocketAddr,
    transport: Transport,
    query: &[u8],
    udp_limit: u16,
) -> io::Result<Message> {
    let mut buffer = vec![0; 65535];
    let n = match transport {
        Transport::Udp => {
            let socket = UdpSocket::bind(SocketAddr::new(bind, 0)).await?;
            socket.connect(peer).await?;
            socket.send(query).await?;
            let n = socket.recv(&mut buffer).await?;
            if n > usize::from(udp_limit) {
                return Err(invalid("reply exceeds advertised UDP payload"));
            }
            n
        }
        Transport::Tcp => {
            let socket = if peer.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(bind, 0))?;
            let mut stream = socket.connect(peer).await?;
            stream.set_nodelay(true)?;
            stream.write_u16(query.len() as u16).await?;
            stream.write_all(query).await?;
            let n = stream.read_u16().await? as usize;
            if n < 12 {
                return Err(invalid("short DNS frame"));
            }
            stream.read_exact(&mut buffer[..n]).await?;
            n
        }
    };
    complete_message(&buffer[..n])
}
pub async fn probe(
    bind: IpAddr,
    lane: Lane,
    mut expected: Vec<Message>,
    accepted: Vec<usize>,
    ordinal: u64,
    deadline_ms: u64,
    seed: u64,
) -> Outcome {
    let start = Instant::now();
    if lane.fresh {
        let old = expected[0].queries[0].name().clone();
        let Ok(name) = hickory_proto::rr::Name::from_ascii(format!(
            "q-{seed:016x}-{ordinal:016x}.{}",
            old.to_ascii()
        )) else {
            return Outcome::Error;
        };
        for template in &mut expected {
            template.queries[0].set_name(name.clone());
            for rr in template
                .answers
                .iter_mut()
                .chain(&mut template.authorities)
                .chain(&mut template.additionals)
            {
                if rr.name == old {
                    rr.name = name.clone();
                }
            }
        }
    }
    let mut request = Message::query();
    request.metadata.id = ordinal as u16;
    request.metadata.recursion_desired = true;
    request.metadata.checking_disabled = expected[0].metadata.checking_disabled;
    request.queries = expected[0].queries.clone();
    // Only the EDNS request envelope is derived from the explicitly frozen fixture.
    request.edns = expected[0].edns.clone();
    let Ok(bytes) = request.to_vec() else {
        return Outcome::Error;
    };
    let result = tokio::time::timeout(std::time::Duration::from_millis(deadline_ms), async {
        let mut reply = exchange(
            bind,
            lane.endpoint,
            lane.transport,
            &bytes,
            request.max_payload(),
        )
        .await?;
        if reply.metadata.truncation && lane.tcp_fallback {
            if !accepted
                .iter()
                .any(|&i| valid(&request, &reply, &expected[i], lane.ttl_floor, true))
            {
                return Ok::<_, io::Error>(false);
            }
            reply = exchange(
                bind,
                lane.endpoint,
                Transport::Tcp,
                &bytes,
                request.max_payload(),
            )
            .await?;
        }
        Ok(accepted
            .iter()
            .any(|&i| valid(&request, &reply, &expected[i], lane.ttl_floor, false)))
    })
    .await;
    match result {
        Ok(Ok(correct)) => Outcome::Reply {
            us: start.elapsed().as_micros() as u64,
            wrong: !correct,
        },
        Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => Outcome::Reply {
            us: start.elapsed().as_micros() as u64,
            wrong: true,
        },
        Ok(Err(_)) => Outcome::Error,
        Err(_) => Outcome::Timeout,
    }
}
