pub mod context;
pub mod keygen;
pub(crate) mod keygen_state_machine;
pub mod signing;
pub(crate) mod signing_state_machine;

use blueprint_sdk as sdk;
use sdk::crypto::hashing::sha2_256;

const META_SALT: &str = "bls-protocol";
/// Helper function to compute deterministic hashes for the BLS processes.
/// Note: for signing, the "call_id" should be the call_id of the preceeding
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
