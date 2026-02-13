use crate::keygen_state_machine::BlsState;
use blueprint_sdk::clients::BlueprintServicesClient;
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::service_handle::NetworkServiceHandle;
use blueprint_sdk::runner::config::BlueprintEnvironment;
use blueprint_sdk::stores::local_database::LocalDatabase;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// The network protocol version for the BLS service
pub(crate) const NETWORK_PROTOCOL: &str = "bls/gennaro/1.0.0";

/// Global BLS context, initialized once at startup.
static BLS_CTX: OnceLock<BlsContext> = OnceLock::new();

/// Get the global BLS context. Panics if not initialized.
pub fn bls_ctx() -> &'static BlsContext {
    BLS_CTX.get().expect("BlsContext not initialized")
}

/// BLS Service Context that holds all the necessary context for the service.
#[derive(Clone)]
pub struct BlsContext {
    pub env: BlueprintEnvironment,
    pub network_backend: NetworkServiceHandle<K256Ecdsa>,
    pub store: Arc<LocalDatabase<BlsState>>,
}

impl BlsContext {
    /// Creates and globally initializes the BLS context.
    pub async fn init(env: &BlueprintEnvironment) -> Result<(), String> {
        let tangle_client = env.tangle_client().await.map_err(|e| e.to_string())?;

        let operators = tangle_client
            .get_operators()
            .await
            .map_err(|e| e.to_string())?;

        let operator_keys =
            blueprint_sdk::networking::service::AllowedKeys::<K256Ecdsa>::EvmAddresses(
                operators.keys().cloned().collect(),
            );

        let (_allowed_keys_tx, allowed_keys_rx) = crossbeam_channel::unbounded();

        let network_config = env
            .libp2p_network_config::<K256Ecdsa>(NETWORK_PROTOCOL, false)
            .map_err(|e| e.to_string())?;

        let network_backend = env
            .libp2p_start_network(network_config, operator_keys, allowed_keys_rx)
            .map_err(|e| e.to_string())?;

        let keystore_dir = PathBuf::from(&env.keystore_uri).join("bls.json");
        let store = Arc::new(
            LocalDatabase::open(keystore_dir).map_err(|e| format!("Failed to open store: {e}"))?,
        );

        let ctx = BlsContext {
            env: env.clone(),
            network_backend,
            store,
        };

        BLS_CTX
            .set(ctx)
            .map_err(|_| "BlsContext already initialized".to_string())
    }

    /// Returns the blueprint ID
    pub fn blueprint_id(&self) -> Result<u64, String> {
        self.env
            .protocol_settings
            .tangle()
            .map(|c| c.blueprint_id)
            .map_err(|err| format!("Blueprint ID not found: {err}"))
    }
}
