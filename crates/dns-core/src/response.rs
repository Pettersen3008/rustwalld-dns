use hickory_proto::op::{Message, Metadata, ResponseCode};
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
