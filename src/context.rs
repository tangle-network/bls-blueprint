use crate::keygen_state_machine::BlsState;
use blueprint_sdk as sdk;
use blueprint_sdk::clients::BlueprintServicesClient;
use color_eyre::Result;
use color_eyre::eyre::eyre;
use sdk::contexts::tangle::TangleClientContext;
use sdk::crypto::sp_core::{SpEcdsa, SpEcdsaPublic};
use sdk::crypto::tangle_pair_signer::sp_core;
use sdk::macros::context::{KeystoreContext, ServicesContext, TangleClientContext};
use sdk::networking::AllowedKeys;
use sdk::networking::service_handle::NetworkServiceHandle;
use sdk::runner::config::BlueprintEnvironment;
use sdk::stores::local_database::LocalDatabase;
use std::sync::Arc;

/// The network protocol version for the BLS service
pub(crate) const NETWORK_PROTOCOL: &str = "bls/gennaro/1.0.0";

/// BLS Service Context that holds all the necessary context for the service
/// to run. This structure implements various traits for keystore, client, and service
/// functionality.
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext)]
pub struct BlsContext {
    #[config]
    pub config: BlueprintEnvironment,
    pub network_backend: NetworkServiceHandle<SpEcdsa>,
    pub store: Arc<LocalDatabase<BlsState>>,
    pub identity: sp_core::ecdsa::Pair,
    #[allow(dead_code)]
    update_allowed_keys: crossbeam_channel::Sender<AllowedKeys<SpEcdsa>>,
}

// Core context management implementation
impl BlsContext {
    /// Creates a new service context with the provided configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Network initialization fails
    /// - Configuration is invalid
    pub async fn new(config: BlueprintEnvironment) -> Result<Self> {
        let service_operators = config.tangle_client().await?.get_operators().await?;
        let allowed_keys = service_operators
            .values()
            .map(|k| SpEcdsaPublic(*k))
            .collect();

        let network_config = config.libp2p_network_config::<SpEcdsa>(NETWORK_PROTOCOL, false)?;
        let identity = network_config.instance_key_pair.0.clone();

        let (tx, rx) = crossbeam_channel::unbounded();
        let network_backend = config.libp2p_start_network(
            network_config,
            AllowedKeys::<SpEcdsa>::InstancePublicKeys(allowed_keys),
            rx,
        )?;

        let store_path = config.data_dir.join("bls.json");
        let store = Arc::new(LocalDatabase::open(store_path)?);

        Ok(Self {
            store,
            identity,
            config,
            network_backend,
            update_allowed_keys: tx,
        })
    }

    /// Returns a reference to the configuration
    #[inline]
    pub fn config(&self) -> &BlueprintEnvironment {
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
}
