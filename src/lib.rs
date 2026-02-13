pub mod context;
pub use context::BlsContext;
pub mod keygen;
pub use keygen::keygen;
pub(crate) mod keygen_state_machine;
pub mod signing;
pub use signing::sign;
pub(crate) mod signing_state_machine;

use blueprint_sdk::Job;
use blueprint_sdk::Router;
use blueprint_sdk::alloy::sol;
use blueprint_sdk::crypto::hashing::sha2_256;
use blueprint_sdk::tangle::TangleLayer;

/// Job IDs
pub const JOB_KEYGEN: u8 = 0;
pub const JOB_SIGN: u8 = 1;

const META_SALT: &str = "bls-protocol";

sol! {
    /// Keygen request: threshold value
    struct KeygenRequest {
        uint16 t;
    }

    /// Keygen result: the generated public key
    struct KeygenResult {
        bytes public_key;
    }

    /// Signing request: keygen call ID + message to sign
    struct SignRequest {
        uint64 keygen_call_id;
        bytes message;
    }

    /// Signing result: the signature
    struct SignResult {
        bytes signature;
    }
}

/// Helper function to compute deterministic hashes for the BLS processes.
/// Note: for signing, the "call_id" should be the call_id of the preceding
/// keygen job
pub fn compute_deterministic_hashes(
    n: u16,
    blueprint_id: u64,
    call_id: u64,
    salt: &'static str,
) -> ([u8; 32], [u8; 32]) {
    let mut data = Vec::with_capacity(
        size_of::<u16>() + size_of::<u64>() + size_of::<u64>() + META_SALT.len(),
    );
    data.extend_from_slice(&n.to_be_bytes());
    data.extend_from_slice(&blueprint_id.to_be_bytes());
    data.extend_from_slice(&call_id.to_be_bytes());
    data.extend_from_slice(META_SALT.as_bytes());

    let meta_hash = sha2_256(&data);

    data.clear();
    data.extend(meta_hash);
    data.extend(salt.as_bytes());

    let deterministic_hash = sha2_256(&data);

    (meta_hash, deterministic_hash)
}

/// Router that maps job IDs to handlers.
pub fn router() -> Router {
    Router::new()
        .route(JOB_KEYGEN, keygen::keygen.layer(TangleLayer))
        .route(JOB_SIGN, signing::sign.layer(TangleLayer))
}
