use bls_blueprint_lib as blueprint;
use blueprint::context::BlsContext;
use blueprint::keygen::KEYGEN_JOB_ID;
use blueprint::signing::SIGN_JOB_ID;
use blueprint_sdk as sdk;
use sdk::Job;
use sdk::serde::BoundedVec;
use sdk::tangle::layers::TangleLayer;
use sdk::tangle::metadata::macros::ext::FieldType;
use sdk::testing::tempfile;
use sdk::testing::utils::setup_log;
use sdk::testing::utils::tangle::InputValue;
use sdk::testing::utils::tangle::TangleTestHarness;
use tokio::time::timeout;

const N: usize = 3;
const T: u16 = 2;

#[tokio::test(flavor = "multi_thread")]
async fn test_blueprint() -> color_eyre::Result<()> {
    color_eyre::install()?;
    setup_log();

    sdk::info!("Running BLS blueprint test");
    let tmp_dir = tempfile::TempDir::new()?;
    let harness = TangleTestHarness::setup(tmp_dir).await?;

    // Setup service
    let (mut test_env, service_id, _blueprint_id) = harness.setup_services::<N>(false).await?;
    test_env.initialize().await?;

    test_env.add_job(blueprint::keygen.layer(TangleLayer)).await;
    test_env.add_job(blueprint::sign.layer(TangleLayer)).await;

    let mut contexts = Vec::new();
    for handle in test_env.node_handles().await {
        let config = handle.gadget_config().await;
        let blueprint_ctx = BlsContext::new(config.clone()).await?;
        contexts.push(blueprint_ctx);
    }

    test_env.start_with_contexts(contexts).await?;

    sdk::info!("Submitting KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id}");

    let job = harness
        .submit_job(service_id, KEYGEN_JOB_ID, vec![InputValue::Uint16(T)])
        .await?;

    let keygen_call_id = job.call_id;
    sdk::info!(
        "Submitted KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id} has call id {keygen_call_id}"
    );

    // Execute job and verify result
    let test_timeout = std::time::Duration::from_secs(60);
    let results = timeout(
        test_timeout,
        harness.wait_for_job_execution(service_id, job),
    )
    .await??;
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

        sdk::info!("Keygen job completed successfully! Moving on to signing ...");
    } else {
        sdk::info!("No expected outputs specified, skipping keygen verification");
    }

    sdk::info!("Submitting SIGNING job {SIGN_JOB_ID} with service ID {service_id}");

    let job_args = vec![
        InputValue::Uint64(keygen_call_id),
        InputValue::List(
            FieldType::Uint8,
            BoundedVec(vec![
                InputValue::Uint8(1),
                InputValue::Uint8(2),
                InputValue::Uint8(3),
            ]),
        ),
    ];

    let job = harness
        .submit_job(service_id, SIGN_JOB_ID, job_args)
        .await?;

    let signing_call_id = job.call_id;
    sdk::info!(
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
        sdk::info!("No expected outputs specified, skipping signing verification");
    }

    Ok(())
}
