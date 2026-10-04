use std::sync::Arc;

use crate::canonical_provider::CanonicalProviderEffect;
use crate::provider_activation::ProviderActivation;

use super::{
    FinalSendBarrier, OnlineFixtureMaterializer, PrimaryProfileFixture, SenderFixture,
    prepare_primary_with_instance,
};

pub(in crate::canonical_provider::composition::tests) fn local_engine_fixture()
-> (SenderFixture, Arc<std::sync::atomic::AtomicUsize>) {
    let profile = runne_daemon_local_engine_effect::LocalEngineTextProfile::from_json(
        include_bytes!("../../../../../../../../docs/profiles/local-engine-text-v1.json"),
    )
    .unwrap();
    let binding = runne_api::ProviderActivationBindingV1::new(
        runne_api::ProviderActivationModeV1::LocalEngineTextV1,
        runne_api::LOCAL_ENGINE_TEXT_PROVIDER_PROFILE_ID,
        runne_api::LOCAL_ENGINE_TEXT_PROVIDER_PROFILE_DIGEST,
    )
    .unwrap();
    let activation = ProviderActivation::from_binding(binding);
    let fixture = PrimaryProfileFixture::new(
        activation,
        profile,
        "local",
        "local-engine-text",
        "v1",
        "provider.local.engine.text",
        // The local profile's canonical provider ID is `local`; this test-only
        // online lifecycle binds that exact authority without a native secret.
        runne_secure_store::ProviderCredentialId::Generic("local"),
    );
    let invocations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let effect = runne_daemon_local_engine_effect::test_effect_with_invocation_counter(Arc::clone(
        &invocations,
    ))
    .unwrap();
    let effect: Arc<dyn CanonicalProviderEffect> =
        crate::canonical_provider::local_engine_effect_adapter(effect);
    let barrier = FinalSendBarrier::new();
    let materializer = OnlineFixtureMaterializer::new("local");
    (
        super::sender_fixture(fixture, effect, barrier, materializer, false),
        invocations,
    )
}

pub(in crate::canonical_provider::composition::tests) async fn assert_cancel_before_local_execution(
    fixture: SenderFixture,
    invocations: Arc<std::sync::atomic::AtomicUsize>,
) {
    let (harness, service) =
        super::build_service(&fixture.profile, Arc::clone(&fixture.effect)).await;
    let prepared = prepare_primary_with_instance(
        &harness,
        &service,
        &fixture.profile,
        fixture.effect.as_ref(),
        0,
    )
    .await;
    let ready = fixture
        .effect
        .stage_effect(prepared.request, prepared.credential)
        .await
        .expect("Local Engine stages a credential-free request");
    runne_application::service::TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        harness.authority(),
    )
    .cancel_task_run(
        &crate::canonical_provider::composition::tests::command_context(
            "018f2e3a-7000-7000-8000-0000000003ff",
            "local-engine-final-send-cancel",
        ),
        runne_application::commands::CancelTaskRunInput {
            taskrun_id: prepared.taskrun_id,
            expected_version: prepared.version,
        },
    )
    .unwrap();
    assert!(matches!(
        fixture
            .effect
            .dispatch_effect(ready, prepared.receipt)
            .await,
        Err(runne_provider::DispatchError::RejectedBeforeEffect(
            runne_provider::ProviderPreEffectRejection::AdapterRejected
        ))
    ));
    assert_eq!(
        fixture
            .materializer
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
}
