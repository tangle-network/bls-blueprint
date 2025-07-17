use crate::context::BlsContext;
use crate::signing_state_machine::SigningMsg;
use blueprint_sdk as sdk;
use round_based::PartyIndex;
use sdk::contexts::tangle::TangleClientContext;
use sdk::crypto::sp_core::SpEcdsa;
use sdk::extract::Context;
use sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use sdk::tangle::extract::{List, TangleArgs2, TangleResult};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Context error: {0}")]
    ContextError(String),
    #[error("Key retrieval error: {0}")]
    KeyRetrievalError(String),
    #[error("MPC error: {0}")]
    MpcError(String),
}

/// Configuration constants for the BLS signing process
const SIGNING_SALT: &str = "bls-signing";

impl From<SigningError> for sdk::Error {
    fn from(err: SigningError) -> Self {
        sdk::Error::Other(err.to_string())
    }
}

pub const SIGN_JOB_ID: u8 = 1;

/// Signs a message using the BLS protocol with a previously generated key
///
/// # Arguments
/// * `message` - The message to sign as a byte vector
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// Returns the signature as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to retrieve the key entry
/// - Signing process failed
pub async fn sign(
    Context(context): Context<BlsContext>,
    TangleArgs2(keygen_call_id, List(message)): TangleArgs2<u64, List<u8>>,
) -> Result<TangleResult<List<u8>>, sdk::Error> {
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    // Setup party information
    let (i, _operators) = context
        .tangle_client()
        .await?
        .get_party_index_and_operators()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let parties: HashMap<PartyIndex, _> = context
        .network_backend
        .peers()
        .into_iter()
        .enumerate()
        .map(|(j, peer_id)| (j as u16, peer_id))
        .collect();

    let n = parties.len() as u16;
    let i = i as u16;

    // Compute hash for key retrieval. Must use the call_id of the keygen job
    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, keygen_call_id, SIGNING_SALT);

    // Retrieve the key entry
    let store_key = hex::encode(meta_hash);
    let mut state = context
        .store
        .get(&store_key)
        .ok_or_else(|| SigningError::KeyRetrievalError("Key entry not found".to_string()))?;

    let t = state.t;

    sdk::info!(
        "Starting BLS Signing for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = RoundBasedNetworkAdapter::<SigningMsg, SpEcdsa>::new(
        context.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let output =
        crate::signing_state_machine::bls_signing_protocol(party, i, n, &mut state, message)
            .await?;

    sdk::info!(
        "Ending BLS Signing for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let signature = output
        .signature
        .ok_or_else(|| SigningError::KeyRetrievalError("Signature not found".to_string()))?;

    // For now, return a placeholder
    Ok(TangleResult(signature.into()))
}
