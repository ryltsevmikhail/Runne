use runne_api::{ProviderReadinessStatusV1, ProviderStatusSnapshotV1};

#[test]
fn v3_peer_requires_one_exact_selected_provider() {
    let (launch, ready, keys) = v3_fixture(false, 6);
    let profile = ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 1_000, &keys)
        .expect("exact V3 readiness");
    let binding = ready.provider_binding();
    let issued = *ready.session_id();
    assert!(
        verify_remote_profile(&profile.peer, v3_remote(&profile, binding, true), issued).is_ok()
    );
    for remote in [
        v3_remote(&profile, binding, false),
        v3_remote_with_status(
            &profile,
            ProviderStatusSnapshotV1::new(
                "openai",
                binding.mode().as_str(),
                binding.profile_id(),
                [0; 32],
                ProviderReadinessStatusV1::CredentialMissing,
                true,
            )
            .expect("mismatched status"),
        ),
        v3_remote_with_two_selected(&profile, binding),
    ] {
        assert!(verify_remote_profile(&profile.peer, remote, issued).is_err());
    }
}

#[test]
fn v3_enrolled_session_carries_the_raised_epoch_for_the_protected_predicate() {
    // The OwnershipMismatch root cause, pinned at the client layer: the V3
    // enrolled profile expects the post-transition epoch, so the connected
    // session exposed to `protected_profile_matches` must carry exactly the
    // raised epoch. A session still on the pre-transition epoch must fail the
    // predicate closed instead of being surfaced to AppCore.
    let (launch, ready, keys) = v3_fixture(false, 6);
    let profile = ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 1_000, &keys)
        .expect("exact V3 readiness");
    assert_eq!(
        profile.peer.expected_authorization_epoch, 1,
        "every daemon launch starts at epoch 0 and the enrollment transition raises it by exactly one"
    );
    let mut session = v3_remote(&profile, ready.provider_binding(), true);
    assert_eq!(
        session.authorization_epoch,
        profile.peer.expected_authorization_epoch
    );
    session.authorization_epoch = 0;
    assert!(
        verify_remote_profile(&profile.peer, session, *ready.session_id()).is_err(),
        "a pre-transition session (epoch 0) must never verify against the enrolled V3 profile"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn v3_status_attestation_survives_exact_remote_profile_client_handoff() {
    let (launch, ready, keys) = v3_fixture(false, 6);
    let profile = ProtectedBundledRuntimeProfile::from_ready_v3(&ready, &launch, 1_000, &keys)
        .expect("exact V3 readiness");
    let remote = v3_remote(&profile, ready.provider_binding(), true);
    let (session, statuses) = verify_remote_profile(&profile.peer, remote, *ready.session_id())
        .expect("exact authenticated remote profile");
    let client = client_from_verified_profile(
        reqwest::Client::new(),
        profile.peer,
        RuntimeCredential::from_local_session([8; 32]),
        session,
        statuses,
        RuntimeTransportKind::ProtectedBundled,
    );

    assert!(crate::canonical::require_status_capability(&client).is_ok());
    assert!(crate::canonical::require_enrollment_capability(&client).is_err());
}

fn v3_remote(
    profile: &ProtectedBundledRuntimeProfile,
    binding: &ProviderActivationBindingV1,
    selected: bool,
) -> SessionRuntimeProfileWire {
    v3_remote_with_status(
        profile,
        ProviderStatusSnapshotV1::new(
            "openai",
            binding.mode().as_str(),
            binding.profile_id(),
            *binding.profile_digest(),
            ProviderReadinessStatusV1::CredentialMissing,
            selected,
        )
        .expect("provider status"),
    )
}

fn v3_remote_with_status(
    profile: &ProtectedBundledRuntimeProfile,
    status: ProviderStatusSnapshotV1,
) -> SessionRuntimeProfileWire {
    let peer = &profile.peer;
    SessionRuntimeProfileWire {
        profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
        schema_hash: crate::GOLDEN_BUNDLE_HASH.to_owned(),
        runtime_version: "0.0.1".to_owned(),
        capabilities: peer.capabilities.clone(),
        capability_digest: hex::encode(peer.capability_digest),
        authority_id: hex::encode(peer.authority_id),
        principal_id: peer.principal_id.clone(),
        event_log_lineage_id: peer.event_log_lineage_id.to_string(),
        daemon_instance_id: peer.daemon_instance_id.to_string(),
        launch_generation: peer.launch_generation,
        session_id: hex::encode(peer.expected_session_id.expect("session")),
        authorization_epoch: peer.expected_authorization_epoch,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: hex::encode(peer.certificate_sha256),
        provider_statuses: vec![status],
    }
}

fn v3_remote_with_two_selected(
    profile: &ProtectedBundledRuntimeProfile,
    binding: &ProviderActivationBindingV1,
) -> SessionRuntimeProfileWire {
    let mut remote = v3_remote(profile, binding, true);
    let deepseek = ProviderActivationBindingV1::deepseek_responses_text_v1();
    remote.provider_statuses.push(
        ProviderStatusSnapshotV1::new(
            "deepseek",
            deepseek.mode().as_str(),
            deepseek.profile_id(),
            *deepseek.profile_digest(),
            ProviderReadinessStatusV1::CredentialMissing,
            true,
        )
        .expect("second status"),
    );
    remote
}
