use crate::context::BlsContext;
use blueprint_sdk as sdk;
use round_based::PartyIndex;
use sdk::error::Error as GadgetError;
use sdk::event_listeners::tangle::events::TangleEventListener;
use sdk::event_listeners::tangle::services::{services_post_processor, services_pre_processor};
use sdk::job;
use sdk::logging;
use sdk::networking::round_based_compat::NetworkDeliveryWrapper;
use sdk::networking::GossipMsgPublicKey;
use sdk::tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled;
use std::collections::BTreeMap;

#[job(
    id = 0,
    params(t),
    event_listener(
        listener = TangleEventListener<BlsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a distributed key generation (DKG) process using the BLS protocol
///
/// # Arguments
/// * `t` - Threshold value for the DKG process
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// Returns the generated public key as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to get party information
/// - MPC protocol execution failed
/// - Serialization of results failed
pub async fn keygen(t: u16, context: BlsContext) -> Result<Vec<u8>, GadgetError> {
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;
    let call_id = context
        .current_call_id()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    // Setup party information
    let (i, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, GossipMsgPublicKey> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as PartyIndex, GossipMsgPublicKey(ecdsa)))
        .collect();

    let n = parties.len() as u16;
    let i = i as u16;

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, KEYGEN_SALT);

    logging::info!(
        "Starting BLS Keygen for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i,
        deterministic_hash,
        parties.clone(),
    );

    let party = round_based::party::MpcParty::connected(network);

    let output = crate::keygen_state_machine::bls_keygen_protocol(party, i, t, n, call_id).await?;

    logging::info!(
        "Ending BLS Keygen for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let public_key = output
        .uncompressed_pk
        .clone()
        .ok_or_else(|| KeygenError::MpcError("Public key missing".to_string()))?;

    // Store the results
    let store_key = hex::encode(meta_hash);
    context.store.set(&store_key, output);

    Ok(public_key)
}

/// Configuration constants for the BLS keygen process
const KEYGEN_SALT: &str = "bls-keygen";

/// Error type for keygen-specific operations
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

impl From<KeygenError> for GadgetError {
    fn from(err: KeygenError) -> Self {
        GadgetError::Other(err.to_string())
    }
}
