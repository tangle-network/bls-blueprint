use bls_blueprint::context::BlsContext;
use blueprint_sdk as sdk;
use blueprint_sdk::crypto::tangle_pair_signer::sp_core::Pair;
use color_eyre::Result;
use sdk::logging;
use sdk::runners::core::runner::BlueprintRunner;
use sdk::runners::tangle::tangle::TangleConfig;

#[sdk::main(env)]
async fn main() {
    let context = BlsContext::new(env.clone())?;

    logging::info!(
        "Starting the Blueprint Runner for {} ...",
        hex::encode(context.identity.public())
    );

    logging::info!("~~~ Executing the BLS blueprint ~~~");

    let tangle_config = TangleConfig::default();
    let keygen = bls_blueprint::keygen::KeygenEventHandler::new(&env, context.clone()).await?;
    let signing = bls_blueprint::signing::SignEventHandler::new(&env, context.clone()).await?;

    BlueprintRunner::new(tangle_config, env.clone())
        .job(keygen)
        .job(signing)
        .run()
        .await?;

    logging::info!("Exiting...");
    Ok(())
}
