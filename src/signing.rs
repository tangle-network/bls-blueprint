use crate::context::BlsContext;
use crate::signing_state_machine::SigningMsg;
use blueprint_sdk as sdk;
use sdk::error::Error as GadgetError;
use sdk::event_listeners::tangle::events::TangleEventListener;
use sdk::event_listeners::tangle::services::{services_post_processor, services_pre_processor};
use sdk::job;
use sdk::logging;
use sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use sdk::networking::InstanceMsgPublicKey;
use sdk::tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled;
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

impl From<SigningError> for GadgetError {
    fn from(err: SigningError) -> Self {
        GadgetError::Other(err.to_string())
    }
}

#[job(
    id = 1,
    params(keygen_call_id, message),
    event_listener(
        listener = TangleEventListener<BlsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
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
    keygen_call_id: u64,
    message: Vec<u8>,
    context: BlsContext,
) -> Result<Vec<u8>, GadgetError> {
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let call_id = context
        .current_call_id()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    // Setup party information
    let (i, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| SigningError::ContextError(e.to_string()))?;

    let parties: HashMap<u16, InstanceMsgPublicKey> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, InstanceMsgPublicKey(ecdsa)))
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

    logging::info!(
        "Starting BLS Signing for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = RoundBasedNetworkAdapter::<SigningMsg>::new(
        context.network_backend.clone(),
        i,
        parties.clone(),
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let output =
        crate::signing_state_machine::bls_signing_protocol(party, i, n, &mut state, message)
            .await?;

    logging::info!(
        "Ending BLS Signing for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let signature = output
        .signature
        .ok_or_else(|| SigningError::KeyRetrievalError("Signature not found".to_string()))?;

    // For now, return a placeholder
    Ok(signature)
}
