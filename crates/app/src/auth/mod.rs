//! Local identity control plane; independent of DNS policy and query workers.
mod crypto;
mod file;
mod store;
pub use crypto::password_hash;
pub use file::{Role, initialize};
pub use store::{Identity, SessionGrant, SessionIdentity, TokenMetadata};
/// Validate bounded identity JSON without files, network, hashing or secret output.
pub fn validate_document(input: &[u8]) -> Result<(), String> {
    file::decode(input).map(|_| ())
}

pub use file::master_token;
