use super::*;
use runne_application::ports::EventStore;
use runne_application::provider::ProviderRemoteGrantProjection;
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;

#[tokio::test(flavor = "current_thread")]
async fn revoked_secondary_keeps_exact_static_capabilities_without_a_route() {
    let harness = Harness::new().await;
    let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../../../docs/profiles/openai-responses-background-text-v1.json"
    ))
    .unwrap();
    let provider = ProviderId::new(profile.provider_id()).unwrap();
    let spec = ProviderSecondaryProfileGrantSpec::new(
        &provider,
        profile.profile_id(),
        profile.provider_id(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        16_384,
        50_000,
    )
    .unwrap();
    let effect = Arc::new(RecoveryEffect::default());
    let catalog = harness.catalog_for_test(spec.clone());
    let first = harness
        .try_compose_with_mock_secondary(catalog.clone(), effect.clone(), false)
        .await
        .unwrap();
    let original_primary = first.selected_profile_identity();
    let route = first.secondary_profile.as_ref().unwrap();
    let saved = setup::prepare(&harness, &first, route);
    let committer = RuntimeProviderRemoteIdentityCommitter::new(
        Arc::clone(&first.keyring),
        Arc::clone(&first.execution_store),
    );
    let context = futures::executor::block_on(committer.for_new_dispatch(
        &saved.claim,
        &provider,
        &provider,
        route.profile.profile_id(),
    ))
    .unwrap();
    futures::executor::block_on(context.persist_request(&saved.rendered_request)).unwrap();
    futures::executor::block_on(
        context.commit_response_id(&RemoteResponseId::new("resp_revoked_caps").unwrap()),
    )
    .unwrap();
    let binding = first
        .execution_store
        .load_remote_attempt_history(saved.taskrun_id, saved.attempt_id)
        .unwrap()
        .unwrap()
        .request
        .binding;
    let first_caps = first.task_run_effects_static_capabilities(&binding);
    assert!(first_caps.matched_profile);
    assert!(first_caps.capabilities.status_check);
    assert!(!first_caps.capabilities.stream_resume);
    assert!(!first_caps.capabilities.remote_cancel);

    harness.revoke_secondary_spec(spec.clone());
    let recomposed = harness
        .try_compose_at_generation_with_catalog(harness.generation() + 1, Some(catalog))
        .await
        .unwrap();
    assert!(recomposed.secondary_profile.is_none());
    assert_eq!(
        recomposed.selected_profile_identities(),
        vec![original_primary.clone()],
        "revocation leaves the primary selected profile unchanged"
    );
    assert_eq!(recomposed.selected_profile_identity(), original_primary);
    let caps = recomposed.task_run_effects_static_capabilities(&binding);
    let history_after_revocation = recomposed
        .execution_store
        .load_remote_attempt_history(saved.taskrun_id, saved.attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(history_after_revocation.request.binding, binding);
    assert!(
        caps.matched_profile,
        "the old runtime generation remains auditable"
    );
    assert!(caps.capabilities.status_check);
    assert!(!caps.capabilities.stream_resume);
    assert!(caps.capabilities.remote_cancel);

    let alterations: [fn(&mut runne_application::provider::ProviderRemoteAttemptBinding); 7] = [
        |binding: &mut runne_application::provider::ProviderRemoteAttemptBinding| {
            binding.provider_id.push_str("-changed")
        },
        |binding: &mut runne_application::provider::ProviderRemoteAttemptBinding| {
            binding.credential_realm.push_str("-changed")
        },
        |binding: &mut runne_application::provider::ProviderRemoteAttemptBinding| {
            binding.profile_id.push_str("-changed")
        },
        |binding: &mut runne_application::provider::ProviderRemoteAttemptBinding| {
            binding.profile_digest[0] ^= 1
        },
        |binding: &mut runne_application::provider::ProviderRemoteAttemptBinding| {
            binding.pricing_digest[0] ^= 1
        },
        |binding: &mut runne_application::provider::ProviderRemoteAttemptBinding| {
            binding.runtime_authority_id[0] ^= 1
        },
        |binding: &mut runne_application::provider::ProviderRemoteAttemptBinding| {
            binding.database_generation += 1
        },
    ];
    for alter in alterations {
        let mut changed = binding.clone();
        alter(&mut changed);
        let mismatch = recomposed.task_run_effects_static_capabilities(&changed);
        assert!(!mismatch.matched_profile);
        assert!(!mismatch.capabilities.status_check);
        assert!(!mismatch.capabilities.stream_resume);
        assert!(!mismatch.capabilities.remote_cancel);
    }

    let authenticator = recomposed.task_run_effects_authenticator();
    let snapshot = harness
        .store
        .load_task_run_effects_with_remote_authenticator(
            saved.taskrun_id,
            Some(authenticator.as_ref()),
            Some(&crate::canonical_provider::CompiledHistoricalProviderModelResolver),
        )
        .unwrap();
    let remote = snapshot.remote.unwrap();
    assert_eq!(remote.binding, binding);
    assert!(matches!(
        remote.secondary_grant,
        ProviderRemoteGrantProjection::Revoked { .. }
    ));
    assert_eq!(
        remote.credential,
        runne_application::provider::ProviderRemoteCredentialProjection::Ready,
        "grant revocation and credential readiness are independent projections"
    );
    assert_eq!(effect.creates.load(Ordering::SeqCst), 0);
    assert_eq!(effect.checks.load(Ordering::SeqCst), 0);
    assert_eq!(effect.local_cancels.load(Ordering::SeqCst), 0);
    assert_eq!(effect.remote_cancels.load(Ordering::SeqCst), 0);
}
