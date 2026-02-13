use crate::SignRequest;
use crate::SignResult;
use crate::context::bls_ctx;
use crate::signing_state_machine::SigningMsg;
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use blueprint_sdk::info;
use round_based::PartyIndex;
use std::collections::HashMap;

const SIGNING_SALT: &str = "bls-signing";

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Context error: {0}")]
    ContextError(String),
    #[error("Key retrieval error: {0}")]
    KeyRetrievalError(String),
    #[error("MPC error: {0}")]
    MpcError(String),
}

impl From<SigningError> for String {
    fn from(err: SigningError) -> Self {
        err.to_string()
    }
}

/// Signs a message using the BLS protocol with a previously generated key.
///
/// Extracts keygen_call_id and message from the on-chain request, retrieves
/// the stored key share, runs the signing protocol, and returns the signature.
pub async fn sign(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<SignRequest>,
) -> Result<TangleResult<SignResult>, String> {
    let ctx = bls_ctx();
    let keygen_call_id = request.keygen_call_id;
    let message: Vec<u8> = request.message.to_vec();

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

    // Compute hash for key retrieval — must use the call_id of the keygen job
    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, keygen_call_id, SIGNING_SALT);

    // Retrieve the key entry
    let store_key = hex::encode(meta_hash);
    let state = ctx
        .store
        .get(&store_key)
        .map_err(|e| format!("Store error: {e}"))?
        .ok_or_else(|| "Key entry not found for keygen_call_id".to_string())?;

    let t = state.t;

    info!(
        "Starting BLS Signing for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = RoundBasedNetworkAdapter::<SigningMsg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let output =
        crate::signing_state_machine::bls_signing_protocol(party, i, n, &state, message)
            .await?;

    info!(
        "Ending BLS Signing for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let signature = output
        .signature
        .ok_or_else(|| "Signature not found in signing output".to_string())?;

    Ok(TangleResult(SignResult {
        signature: signature.into(),
    }))
}
