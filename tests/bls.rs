use std::future;
use bls_blueprint::keygen::{KeygenEventHandler, KEYGEN_JOB_ID};
use bls_blueprint::signing::{SignEventHandler, SIGN_JOB_ID};

const N: usize = 3;
const T: u16 = 2;

use bls_blueprint::context::BlsContext;
use blueprint_sdk as sdk;
use blueprint_sdk::macros::ext::blueprint_serde::BoundedVec;
use blueprint_sdk::macros::ext::{async_trait, futures};
use blueprint_sdk::macros::ext::async_trait::async_trait;
use blueprint_sdk::runners::core::error::RunnerError;
use blueprint_sdk::runners::core::runner::BackgroundService;
use color_eyre::eyre;
use sdk::logging;
use sdk::testing::tempfile;
use sdk::testing::utils::harness::TestHarness;
use sdk::testing::utils::tangle::InputValue;
use sdk::testing::utils::tangle::TangleTestHarness;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;

#[derive(Clone)]
struct MockBackgroundService;

#[async_trait]
impl BackgroundService for MockBackgroundService {
    async fn start(&self) -> Result<Receiver<Result<(), RunnerError>>, RunnerError> {
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            future::pending::<()>().await;
            let _ = tx.send(Ok(()));
        });
        Ok(rx)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_blueprint() -> color_eyre::Result<()> {
    color_eyre::install()?;
    logging::setup_log();

    logging::info!("Running BLS blueprint test");
    let tmp_dir = tempfile::TempDir::new()?;
    let harness = TangleTestHarness::setup(tmp_dir).await?;

    // Setup service
    let (mut test_env, service_id, _blueprint_id) = harness.setup_services::<N>(false).await?;
    test_env.initialize().await?;
    // test_env.add_job(|config| async move {
    //     // Create blueprint-specific context
    //     let blueprint_ctx = BlsContext::new(config.clone()).unwrap();
    //
    //     KeygenEventHandler::new(&config, blueprint_ctx.clone()).await
    // }).await?;
    // // test_env.add_job(|config| async move {
    // //     // Create blueprint-specific context
    // //     let blueprint_ctx = BlsContext::new(config.clone()).unwrap();
    // //
    // //     SignEventHandler::new(&config, blueprint_ctx.clone()).await
    // // }).await?;

    // Get the alice node
    let handles = test_env.node_handles().await;
    for handle in &handles[1..] {
        let blueprint_ctx = BlsContext::new(handle.gadget_config().await)?;
        std::mem::forget(blueprint_ctx);
        handle.add_background_service(MockBackgroundService).await;
    }

    let alice_handle = handles[0].clone();
    let alice_env = alice_handle.gadget_config().await;

    // Create blueprint-specific context
    let blueprint_ctx = BlsContext::new(alice_env.clone())?;

    // Create the event handlers
    let keygen = KeygenEventHandler::new(&alice_env, blueprint_ctx.clone()).await?;
    let sign = SignEventHandler::new(&alice_env, blueprint_ctx).await?;

    alice_handle.add_job(keygen).await;
    alice_handle.add_job(sign).await;

    test_env.start().await?;

    logging::info!("Submitting KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id}");

    let job = harness
        .submit_job(service_id, KEYGEN_JOB_ID, vec![InputValue::Uint16(T)])
        .await?;

    let keygen_call_id = job.call_id;
    logging::info!(
        "Submitted KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id} has call id {keygen_call_id}"
    );

    // Execute job and verify result
    let results = harness.wait_for_job_execution(service_id, job).await?;
    assert_eq!(results.service_id, service_id);

    let expected_outputs = vec![];
    if !expected_outputs.is_empty() {
        assert_eq!(
            results.result.len(),
            expected_outputs.len(),
            "Number of keygen outputs doesn't match expected"
        );

        for (result, expected) in results.result.into_iter().zip(expected_outputs.into_iter()) {
            assert_eq!(result, expected);
        }

        logging::info!("Keygen job completed successfully! Moving on to signing ...");
    } else {
        logging::info!("No expected outputs specified, skipping keygen verification");
    }

    logging::info!("Submitting SIGNING job {SIGN_JOB_ID} with service ID {service_id}");

    let job_args = vec![
        InputValue::Uint64(keygen_call_id),
        InputValue::List(BoundedVec(vec![
            InputValue::Uint8(1),
            InputValue::Uint8(2),
            InputValue::Uint8(3),
        ])),
    ];

    let job = harness
        .submit_job(service_id, SIGN_JOB_ID, job_args)
        .await?;

    let signing_call_id = job.call_id;
    logging::info!(
        "Submitted SIGNING job {SIGN_JOB_ID} with service ID {service_id} has call id {signing_call_id}",
    );

    let results = harness.wait_for_job_execution(service_id, job).await?;
    assert_eq!(results.service_id, service_id);

    let expected_outputs = vec![];
    if !expected_outputs.is_empty() {
        assert_eq!(
            results.result.len(),
            expected_outputs.len(),
            "Number of signing outputs doesn't match expected"
        );

        for (result, expected) in results.result.into_iter().zip(expected_outputs.into_iter()) {
            assert_eq!(result, expected);
        }
    } else {
        logging::info!("No expected outputs specified, skipping signing verification");
    }

    Ok(())
}
