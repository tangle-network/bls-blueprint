use crate::keygen_state_machine::BlsState;
use blueprint_sdk as sdk;
use color_eyre::eyre::eyre;
use color_eyre::{Report, Result};
use sdk::clients::GadgetServicesClient;
use sdk::config::GadgetConfiguration;
use sdk::contexts::keystore::KeystoreContext;
use sdk::contexts::tangle::TangleClientContext;
use sdk::crypto::sp_core::SpSr25519;
use sdk::crypto::tangle_pair_signer::sp_core;
use sdk::keystore::backends::Backend;
use sdk::logging;
use sdk::macros::contexts::{KeystoreContext, ServicesContext, TangleClientContext};
use sdk::networking::networking::NetworkMultiplexer;
use sdk::stores::local_database::LocalDatabase;
use sdk::tangle_subxt;
use sdk::tangle_subxt::tangle_testnet_runtime::api;
use sp_core::ecdsa::Public;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tangle_subxt::subxt_core::utils::AccountId32;

/// The network protocol version for the BLS service
const NETWORK_PROTOCOL: &str = "/bls/gennaro/1.0.0";

/// BLS Service Context that holds all the necessary context for the service
/// to run. This structure implements various traits for keystore, client, and service
/// functionality.
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext)]
pub struct BlsContext {
    #[config]
    pub config: GadgetConfiguration,
    #[call_id]
    pub call_id: Option<u64>,
    pub network_backend: Arc<NetworkMultiplexer>,
    pub store: Arc<LocalDatabase<BlsState>>,
    pub identity: sp_core::ecdsa::Pair,
}

// Core context management implementation
impl BlsContext {
    /// Creates a new service context with the provided configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - Network initialization fails
    /// - Configuration is invalid
    pub fn new(config: GadgetConfiguration) -> Result<Self> {
        let network_config = config
            .libp2p_network_config(NETWORK_PROTOCOL)
            .map_err(|err| eyre!("Failed to create network configuration: {err}"))?;

        let identity = network_config.secret_key.0.clone();
        let gossip_handle = sdk::networking::setup::start_p2p_network(network_config)
            .map_err(|err| eyre!("Failed to start the P2P network: {err}"))?;

        let keystore_dir = PathBuf::from(&config.keystore_uri).join("bls.json");
        let store = Arc::new(LocalDatabase::open(keystore_dir));

        Ok(Self {
            store,
            identity,
            call_id: None,
            config,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
        })
    }

    /// Returns a reference to the configuration
    #[inline]
    pub fn config(&self) -> &GadgetConfiguration {
        &self.config
    }

    /// Returns a clone of the store handle
    #[inline]
    pub fn store(&self) -> Arc<LocalDatabase<BlsState>> {
        self.store.clone()
    }

    /// Returns the network protocol version
    #[inline]
    pub fn network_protocol(&self) -> &str {
        NETWORK_PROTOCOL
    }
}

// Protocol-specific implementations
impl BlsContext {
    /// Retrieves the current blueprint ID from the configuration
    ///
    /// # Errors
    /// Returns an error if the blueprint ID is not found in the configuration
    pub fn blueprint_id(&self) -> Result<u64> {
        self.config()
            .protocol_settings
            .tangle()
            .map(|c| c.blueprint_id)
            .map_err(|err| eyre!("Blueprint ID not found in configuration: {err}"))
    }

    /// Retrieves the current party index and operator mapping
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to retrieve operator keys
    /// - Current party is not found in the operator list
    pub async fn get_party_index_and_operators(
        &self,
    ) -> Result<(usize, BTreeMap<AccountId32, Public>)> {
        let parties = self.current_service_operators_ecdsa_keys().await?;
        let my_id = self.keystore().first_local::<SpSr25519>()?.0;

        logging::trace!(
            "Looking for {my_id:?} in parties: {:?}",
            parties.keys().collect::<Vec<_>>()
        );

        let index_of_my_id = parties
            .iter()
            .position(|(id, _)| id.0 == *my_id)
            .ok_or_else(|| eyre!("Party not found in operator list"))?;

        Ok((index_of_my_id, parties))
    }

    /// Retrieves the ECDSA keys for all current service operators
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to connect to the Tangle client
    /// - Failed to retrieve operator information
    /// - Missing ECDSA key for any operator
    pub async fn current_service_operators_ecdsa_keys(
        &self,
    ) -> Result<BTreeMap<AccountId32, Public>> {
        let client = self.tangle_client().await?;
        let current_blueprint = self.blueprint_id()?;
        let storage = client.storage().at_latest().await?;

        let mut map = BTreeMap::new();
        for (operator, _) in client.get_operators().await? {
            let addr = api::storage()
                .services()
                .operators(current_blueprint, &operator);

            let maybe_pref = storage
                .fetch(&addr)
                .await
                .map_err(|err| eyre!("Failed to fetch operator storage for {operator}: {err}"))?;

            if let Some(pref) = maybe_pref {
                let public_key = Public::from_full(pref.key.as_slice())
                    .map_err(|_| Report::msg("Invalid key"))?;
                map.insert(operator, public_key);
            } else {
                return Err(eyre!("Missing ECDSA key for operator {operator}"));
            }
        }

        Ok(map)
    }

    /// Retrieves the current call ID for this job
    ///
    /// # Errors
    /// Returns an error if failed to retrieve the call ID from storage
    pub async fn current_call_id(&self) -> Result<u64> {
        let client = self.tangle_client().await?;
        let addr = api::storage().services().next_job_call_id();
        let storage = client.storage().at_latest().await?;

        let maybe_call_id = storage
            .fetch_or_default(&addr)
            .await
            .map_err(|err| eyre!("Failed to fetch current call ID: {err}"))?;

        Ok(maybe_call_id.saturating_sub(1))
    }
}
