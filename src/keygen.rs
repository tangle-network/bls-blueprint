use crate::KeygenRequest;
use crate::KeygenResult;
use crate::context::bls_ctx;
use crate::keygen_state_machine::KeygenMsg;
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::info;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use round_based::PartyIndex;
use std::collections::HashMap;

const KEYGEN_SALT: &str = "bls-keygen";

/// Runs a distributed key generation (DKG) process using the BLS protocol.
///
/// Extracts threshold `t` from the on-chain request, runs the Gennaro DKG
/// protocol via round-based networking, and returns the aggregated public key.
pub async fn keygen(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<KeygenRequest>,
) -> Result<TangleResult<KeygenResult>, String> {
    let ctx = bls_ctx();
    let t = request.t;

    // Get party info from connected peers
    let mut all_peers = ctx.network_backend.peers();
    let local_peer_id = ctx.network_backend.local_peer_id;
    if !all_peers.contains(&local_peer_id) {
        all_peers.push(local_peer_id);
    }
    all_peers.sort();

    let n = all_peers.len() as u16;
    let i = all_peers
        .iter()
        .position(|p| *p == local_peer_id)
        .ok_or_else(|| "Local peer not found in peer list".to_string())? as u16;

    let parties: HashMap<PartyIndex, libp2p::PeerId> = all_peers
        .into_iter()
        .enumerate()
        .map(|(idx, peer_id)| (idx as PartyIndex, peer_id))
        .collect();

    let blueprint_id = ctx.blueprint_id()?;
    let call_id = 0u64; // Deterministic from on-chain context

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, KEYGEN_SALT);

    info!(
        "Starting BLS Keygen for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = RoundBasedNetworkAdapter::<KeygenMsg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let output = crate::keygen_state_machine::bls_keygen_protocol(party, i, t, n, call_id).await?;

    info!(
        "Ending BLS Keygen for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let public_key = output
        .uncompressed_pk
        .clone()
        .ok_or_else(|| "Public key missing from keygen output".to_string())?;

    // Store the results
    let store_key = hex::encode(meta_hash);
    let _ = ctx.store.set(&store_key, output);

    Ok(TangleResult(KeygenResult {
        public_key: public_key.into(),
    }))
}

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("Failed to serialize data: {0}")]
    SerializationError(String),

    #[error("MPC protocol error: {0}")]
    MpcError(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("Delivery error: {0}")]
    DeliveryError(String),
}

impl From<KeygenError> for String {
    fn from(err: KeygenError) -> Self {
        err.to_string()
    }
}
