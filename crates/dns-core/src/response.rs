use hickory_proto::op::{Message, Metadata, ResponseCode};
pub(crate) fn blocked(request: &Message, mode: rustwalld_dns_policy::BlockMode) -> Message {
    use hickory_proto::rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    };
    use rustwalld_dns_policy::BlockMode;
    let mut response = reply(
        request,
        if mode == BlockMode::NxDomain {
            ResponseCode::NXDomain
        } else {
            ResponseCode::NoError
        },
    );
    if mode == BlockMode::NullIp
        && let Some(question) = request.queries.first()
    {
        let data = match question.query_type() {
            RecordType::A => Some(RData::A(A(std::net::Ipv4Addr::UNSPECIFIED))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(std::net::Ipv6Addr::UNSPECIFIED))),
            _ => None,
        };
        if let Some(data) = data {
            response.add_answer(Record::from_rdata(question.name().clone(), 60, data));
        }
    }
    response
}
/// A response to `request` with `code`, echoing at most its first question.
pub fn reply(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata = Metadata::response_from_request(&request.metadata);
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    // An invalid multiple-question message need not echo every question.
    response
        .queries
        .extend(request.queries.iter().take(1).cloned());
    response
}
