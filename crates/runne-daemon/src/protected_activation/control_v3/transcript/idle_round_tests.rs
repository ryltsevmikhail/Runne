use super::take_idle_enrollment_session;
use crate::application::provider_credential_enrollment::{
    test_control, test_http_status_facts_available, DaemonProtectedCredentialEnrollmentSession,
};
use runne_api::ProviderCredentialProviderV2;
use std::sync::Arc;

#[test]
fn idle_round_captures_all_http_controls_before_taking_session() {
    let (primary, keys) = test_control();
    let (background, _) = test_control();
    let (owned, _, _) = crate::protected_activation::test_enrollment_owned_and_sessions();
    let session = primary
        .start_protected_session_with_controls(
            &keys,
            &owned,
            crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
            vec![primary.clone(), background.clone()],
        )
        .unwrap();
    assert!(session.is_idle());
    let mut active: Option<DaemonProtectedCredentialEnrollmentSession> = Some(session);

    let transfer = take_idle_enrollment_session(&mut active)
        .unwrap()
        .expect("idle session transfers to next round");

    assert!(active.is_none(), "old session is consumed exactly once");
    assert_eq!(transfer.http_controls.len(), 2);
    assert!(Arc::ptr_eq(&transfer.http_controls[0], &primary));
    assert!(Arc::ptr_eq(&transfer.http_controls[1], &background));
    drop(transfer.rendezvous);
}

#[test]
fn idle_round_rotation_refreshes_both_realm_controls_and_preserves_approval_fence() {
    use runne_api::provider_credential_enrollment::linux_activation_policy::{
        LinuxEnrollmentActivationRecord, LinuxEnrollmentScope, LinuxInstallationFacts,
        ACTIVATION_RECORD_FILE,
    };
    use std::os::unix::fs::PermissionsExt as _;

    let (mut primary, keys) = test_control();
    let (mut background, _) = test_control();
    let (owned, _, _) = crate::protected_activation::test_enrollment_owned_and_sessions();
    let authority = *owned.stable().authority_id();
    Arc::get_mut(&mut primary)
        .unwrap()
        .test_set_runtime_authority(authority);
    Arc::get_mut(&mut background)
        .unwrap()
        .test_set_runtime_authority(authority);
    let controls = vec![primary.clone(), background.clone()];

    let root = tempfile::tempdir().unwrap();
    let install = LinuxInstallationFacts {
        runtime_root_digest: [31; 32],
        desktop_image_digest: [32; 32],
        writer_image_digest: [33; 32],
        daemon_image_digest: [34; 32],
        runtime_authority_id: authority,
        machine_id_digest: [35; 32],
    };
    let approval = LinuxEnrollmentActivationRecord {
        provider_scope: LinuxEnrollmentScope::Catalog,
        runtime_root_digest: install.runtime_root_digest,
        desktop_image_digest: install.desktop_image_digest,
        writer_image_digest: install.writer_image_digest,
        daemon_image_digest: install.daemon_image_digest,
        runtime_authority_id: authority,
        machine_id_digest: install.machine_id_digest,
        approved_at_unix_millis: 1,
    };
    let approval_path = root.path().join(ACTIVATION_RECORD_FILE);
    std::fs::write(&approval_path, approval.to_config_json()).unwrap();
    std::fs::set_permissions(&approval_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    crate::protected_activation::enrollment_control_fanout::install_linux_preadmission(
        &controls,
        &owned,
        root.path(),
        install,
    )
    .unwrap();

    let session = primary
        .start_protected_session_with_controls(
            &keys,
            &owned,
            crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
            controls.clone(),
        )
        .unwrap();
    let prior_session = *owned.session_id();
    assert!(test_http_status_facts_available(&primary, prior_session));
    assert!(test_http_status_facts_available(&background, prior_session));
    let mut active = Some(session);
    let transfer = take_idle_enrollment_session(&mut active)
        .unwrap()
        .expect("idle round transfers the live controls");

    let mut renewal =
        runne_api::ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), 1, [17; 32])
            .unwrap();
    renewal.sign(&keys);
    let next_session = *uuid::Uuid::now_v7().as_bytes();
    let mut ticket = runne_api::ProtectedCredentialEnrollmentRenewTicketV3::new(
        &renewal,
        next_session,
        [18; 32],
        1_000,
        31_000,
    )
    .unwrap();
    ticket.sign(&keys);
    let next_owned = ticket
        .verify_exact_at(&renewal, 1_000, &keys)
        .unwrap()
        .next_owned_launch();
    assert_ne!(next_owned.session_id(), owned.session_id());
    crate::protected_activation::enrollment_control_fanout::rebind_linux_preadmission(
        &transfer.http_controls,
        prior_session,
        next_session,
    )
    .unwrap();
    let refreshed = primary
        .start_protected_session_with_controls(
            &keys,
            &next_owned,
            transfer.rendezvous,
            transfer.http_controls,
        )
        .unwrap();

    for control in [&primary, &background] {
        assert!(!test_http_status_facts_available(control, prior_session));
        assert!(test_http_status_facts_available(control, next_session));
        assert!(!control.test_linux_preadmission_allows(
            prior_session,
            authority,
            ProviderCredentialProviderV2::OpenAiBackground
        ));
        assert!(control.test_linux_preadmission_allows(
            next_session,
            authority,
            ProviderCredentialProviderV2::OpenAiBackground
        ));
    }

    refreshed.clear_http_facts();
    std::fs::remove_file(approval_path).unwrap();
    for control in [&primary, &background] {
        assert!(
            !control.test_linux_preadmission_allows(
                next_session,
                authority,
                ProviderCredentialProviderV2::OpenAiBackground
            ),
            "removed approval denies both realm controls"
        );
    }
}
