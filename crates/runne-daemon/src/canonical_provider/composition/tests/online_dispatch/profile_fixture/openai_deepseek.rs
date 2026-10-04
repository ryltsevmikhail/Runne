use std::sync::Arc;

use runne_application::commands::CancelTaskRunInput;
use runne_application::service::TaskRunService;
use runne_secure_store::ProviderCredentialDispatchMaterializer;

use crate::canonical_provider::CanonicalProviderEffect;
use crate::provider_activation::ProviderActivation;

use super::http_probe::PostProbe;
use super::paused_materializer::{MaterializationBarrier, PausedMaterializer};
use super::{PrimaryProfileFixture, build_service, prepare_primary_with_instance};

pub(in crate::canonical_provider::composition::tests) async fn openai_foreground_fixture_cancellation_denies_post()
 {
    let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .unwrap();
    let activation = ProviderActivation::from_binding(
        runne_api::ProviderActivationBindingV1::openai_responses_text_v1(),
    );
    let daemon_profile = crate::canonical_provider::OpenAiTextProviderProfile::new(profile.clone());
    let fixture = PrimaryProfileFixture::new(
        activation,
        daemon_profile,
        "openai",
        runne_provider_openai::OPENAI_MODEL_ID,
        runne_provider_openai::OPENAI_MODEL_REVISION,
        "provider.openai.responses.text",
        runne_secure_store::ProviderCredentialId::Generic("openai"),
    );
    let barrier = MaterializationBarrier::new();
    let materializer = PausedMaterializer::new("openai", Arc::clone(&barrier));
    let erased: Arc<dyn ProviderCredentialDispatchMaterializer> = materializer.clone();
    let probe = PostProbe::start("api.openai.com").await;
    let policy = runne_provider_openai::OpenAiTransportPolicy::for_profile(&profile).unwrap();
    let client = runne_daemon_openai_effect::loopback_fixture_client(
        &policy,
        probe.address,
        &probe.certificate,
    )
    .unwrap();
    let sender =
        runne_daemon_openai_effect::effect_from_loopback_fixture_with_materializer(client, erased)
            .unwrap();
    let effect: Arc<dyn CanonicalProviderEffect> =
        crate::canonical_provider::openai_effect_adapter(sender);
    assert_cancel_before_materialization(fixture, effect, materializer, barrier, probe, 0xD1).await;
}

pub(in crate::canonical_provider::composition::tests) async fn deepseek_foreground_fixture_cancellation_denies_post()
 {
    let profile = runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .unwrap();
    let activation = ProviderActivation::from_binding(
        runne_api::ProviderActivationBindingV1::deepseek_responses_text_v1(),
    );
    let fixture = PrimaryProfileFixture::new(
        activation,
        profile.clone(),
        "deepseek",
        runne_provider_deepseek::DEEPSEEK_MODEL_ID,
        runne_provider_deepseek::DEEPSEEK_MODEL_REVISION,
        "provider.deepseek.responses.text",
        runne_secure_store::ProviderCredentialId::DeepSeek,
    );
    let barrier = MaterializationBarrier::new();
    let materializer = PausedMaterializer::new("deepseek", Arc::clone(&barrier));
    let erased: Arc<dyn ProviderCredentialDispatchMaterializer> = materializer.clone();
    let probe = PostProbe::start("api.deepseek.com").await;
    let policy = runne_provider_deepseek::DeepSeekTransportPolicy::for_profile(&profile).unwrap();
    let client = runne_daemon_deepseek_effect::loopback_fixture_client(
        &policy,
        probe.address,
        &probe.certificate,
    )
    .unwrap();
    let sender = runne_daemon_deepseek_effect::effect_from_loopback_fixture_with_materializer(
        client, erased,
    )
    .unwrap();
    let effect: Arc<dyn CanonicalProviderEffect> =
        crate::canonical_provider::deepseek_effect_adapter(sender);
    assert_cancel_before_materialization(fixture, effect, materializer, barrier, probe, 0xD2).await;
}

async fn assert_cancel_before_materialization(
    profile: PrimaryProfileFixture,
    effect: Arc<dyn CanonicalProviderEffect>,
    materializer: Arc<PausedMaterializer>,
    barrier: Arc<MaterializationBarrier>,
    probe: PostProbe,
    suffix: u8,
) {
    let (harness, service) = build_service(&profile, Arc::clone(&effect)).await;
    let prepared =
        prepare_primary_with_instance(&harness, &service, &profile, effect.as_ref(), 0).await;
    let ready = effect
        .stage_effect(prepared.request, prepared.credential)
        .await
        .expect("actual online sender stages the receipt-bound request");
    let pending_materialization = barrier.wait_until_entered();
    tokio::pin!(pending_materialization);
    let sender = Arc::clone(&effect);
    let dispatch =
        tokio::spawn(async move { sender.dispatch_effect(ready, prepared.receipt).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        &mut pending_materialization,
    )
    .await
    .expect("point-of-use credential materializer barrier");
    TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        harness.authority(),
    )
    .cancel_task_run(
        &crate::canonical_provider::composition::tests::command_context(
            &format!("018f2e3a-7000-7000-8000-{suffix:02x}0000000001"),
            &format!("foreground-cancel-{suffix}"),
        ),
        CancelTaskRunInput {
            taskrun_id: prepared.taskrun_id,
            expected_version: prepared.version,
        },
    )
    .unwrap();
    barrier.release();
    assert!(matches!(
        dispatch.await.unwrap(),
        Err(runne_provider::DispatchError::RejectedBeforeEffect(
            runne_provider::ProviderPreEffectRejection::AdapterRejected
        ))
    ));
    assert_eq!(materializer.calls(), 1);
    let posts = Arc::clone(&probe.posts);
    probe.finish().await;
    assert_eq!(posts.load(std::sync::atomic::Ordering::SeqCst), 0);
}
