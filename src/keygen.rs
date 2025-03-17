use crate::context::BlsContext;
use crate::keygen_state_machine::KeygenMsg;
use blueprint_sdk as sdk;
use round_based::PartyIndex;
use sdk::contexts::tangle::TangleClientContext;
use sdk::crypto::sp_core::{SpEcdsa, SpEcdsaPublic};
use sdk::extract::Context;
use sdk::networking::discovery::peers::VerificationIdentifierKey;
use sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use sdk::tangle::extract::{CallId, List, TangleArg, TangleResult};
use std::collections::HashMap;

pub const KEYGEN_JOB_ID: u8 = 0;

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
pub async fn keygen(
    Context(context): Context<BlsContext>,
    CallId(call_id): CallId,
    TangleArg(t): TangleArg<u16>,
) -> Result<TangleResult<List<u8>>, sdk::Error> {
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    // Setup party information
    let (i, operators) = context
        .tangle_client()
        .await?
        .get_party_index_and_operators()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;
    let parties: HashMap<u16, VerificationIdentifierKey<SpEcdsa>> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| {
            (
                j as PartyIndex,
                VerificationIdentifierKey::InstancePublicKey(SpEcdsaPublic(ecdsa)),
            )
        })
        .collect();
    let n = parties.len() as u16;
    let i = i as u16;

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, KEYGEN_SALT);

    sdk::info!(
        "Starting BLS Keygen for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let network = RoundBasedNetworkAdapter::<KeygenMsg, SpEcdsa>::new(
        context.network_backend.clone(),
        i,
        parties.clone(),
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let output = crate::keygen_state_machine::bls_keygen_protocol(party, i, t, n, call_id).await?;

    sdk::info!(
        "Ending BLS Keygen for party {i}, n={n}, t={t}, eid={}",
        hex::encode(deterministic_hash)
    );

    let public_key = output
        .uncompressed_pk
        .clone()
        .ok_or_else(|| KeygenError::MpcError("Public key missing".to_string()))?;

    // Store the results
    let store_key = hex::encode(meta_hash);
    context.store.set(&store_key, output)?;

    Ok(TangleResult(public_key.into()))
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

impl From<KeygenError> for sdk::Error {
    fn from(err: KeygenError) -> Self {
        sdk::Error::Other(err.to_string())
    }
}
