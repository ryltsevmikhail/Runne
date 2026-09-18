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
        // The enrolled V3 profile verifies against exactly the raised epoch.
        authorization_epoch: 1,
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
