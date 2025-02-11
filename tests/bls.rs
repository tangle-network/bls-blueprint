use bls_blueprint::keygen::{KeygenEventHandler, KEYGEN_JOB_ID};
use bls_blueprint::signing::SIGN_JOB_ID;

#[expect(dead_code)]
const N: usize = 3;
#[expect(dead_code)]
const T: usize = 2;

use bls_blueprint::context::BlsContext;
use blueprint_sdk as sdk;
use sdk::logging;
use sdk::testing::tempfile;
use sdk::testing::utils::harness::TestHarness;
use sdk::testing::utils::runner::TestEnv;
use sdk::testing::utils::tangle::TangleTestHarness;
use sdk::testing::utils::tangle::{InputValue, OutputValue};

#[tokio::test(flavor = "multi_thread")]
async fn test_blueprint() -> color_eyre::Result<()> {
    color_eyre::install()?;
    logging::setup_log();

    logging::info!("Running BLS blueprint test");
    let tmp_dir = tempfile::TempDir::new()?;
    let harness = TangleTestHarness::setup(tmp_dir).await?;
    let env = harness.env().clone();

    // Create blueprint-specific context
    let blueprint_ctx = BlsContext::new(env.clone())?;

    let handler = KeygenEventHandler::new(&env, blueprint_ctx).await?;

    // Setup service
    let (mut test_env, service_id, _blueprint_id) = harness.setup_services(false).await?;
    test_env.add_job(handler);

    test_env.run_runner().await?;

    logging::info!("Submitting KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id}",);

    // Execute job and verify result
    let results = harness
        .execute_job(
            service_id,
            0,
            vec![InputValue::Uint64(5)],
            vec![OutputValue::Uint64(25)],
        )
        .await?;

    logging::info!(
        "Submitted KEYGEN job {} with service ID {service_id}",
        KEYGEN_JOB_ID
    );

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

    logging::info!(
        "Submitting SIGNING job {} with service ID {service_id}",
        SIGN_JOB_ID
    );

    // let job_args = vec![
    //     InputValue::Uint64(keygen_call_id),
    //     InputValue::List(BoundedVec(vec![
    //         InputValue::Uint8(1),
    //         InputValue::Uint8(2),
    //         InputValue::Uint8(3),
    //     ])),
    // ];
    //
    // let job = submit_job(
    //     client,
    //     &keypair,
    //     service_id,
    //     Job::from(SIGN_JOB_ID),
    //     job_args,
    //     call_id + 1,
    // )
    // .await
    // .expect("Failed to submit job");
    //
    // let signing_call_id = job.call_id;
    // logging::info!(
    //     "Submitted SIGNING job {SIGN_JOB_ID} with service ID {service_id} has call id {signing_call_id}",
    // );
    //
    // let expected_outputs = vec![];
    // if !expected_outputs.is_empty() {
    //     assert_eq!(
    //         job_results.result.len(),
    //         expected_outputs.len(),
    //         "Number of signing outputs doesn't match expected"
    //     );
    //
    //     for (result, expected) in job_results
    //         .result
    //         .into_iter()
    //         .zip(expected_outputs.into_iter())
    //     {
    //         assert_eq!(result, expected);
    //     }
    // } else {
    //     logging::info!("No expected outputs specified, skipping signing verification");
    // }

    Ok(())
}
