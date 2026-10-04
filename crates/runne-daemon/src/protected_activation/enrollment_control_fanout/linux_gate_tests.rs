use super::*;
use crate::application::provider_credential_enrollment::test_control;
use runne_api::ProviderCredentialProviderV2;
use runne_api::provider_credential_enrollment::linux_activation_policy::{
    ACTIVATION_RECORD_FILE, LinuxEnrollmentActivationRecord, LinuxEnrollmentScope,
    LinuxInstallationFacts,
};
use std::os::unix::fs::PermissionsExt as _;

fn gate_fixture() -> (
    runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    tempfile::TempDir,
    LinuxInstallationFacts,
) {
    let (owned, _, _) = crate::protected_activation::test_enrollment_owned_and_sessions();
    let authority = *owned.stable().authority_id();
    let root = tempfile::tempdir().unwrap();
    let facts = LinuxInstallationFacts {
        runtime_root_digest: [31; 32],
        desktop_image_digest: [32; 32],
        writer_image_digest: [33; 32],
        daemon_image_digest: [34; 32],
        runtime_authority_id: authority,
        machine_id_digest: [35; 32],
    };
    let record = LinuxEnrollmentActivationRecord {
        provider_scope: LinuxEnrollmentScope::Catalog,
        runtime_root_digest: facts.runtime_root_digest,
        desktop_image_digest: facts.desktop_image_digest,
        writer_image_digest: facts.writer_image_digest,
        daemon_image_digest: facts.daemon_image_digest,
        runtime_authority_id: authority,
        machine_id_digest: facts.machine_id_digest,
        approved_at_unix_millis: 1,
    };
    let path = root.path().join(ACTIVATION_RECORD_FILE);
    std::fs::write(&path, record.to_config_json()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (owned, root, facts)
}

#[test]
fn linux_preadmission_installs_and_rotates_for_every_realm() {
    let (owned, root, facts) = gate_fixture();
    let authority = *owned.stable().authority_id();
    let (mut primary, _) = test_control();
    let (mut background, _) = test_control();
    Arc::get_mut(&mut primary)
        .unwrap()
        .test_set_runtime_authority(authority);
    Arc::get_mut(&mut background)
        .unwrap()
        .test_set_runtime_authority(authority);
    let controls = [primary.clone(), background.clone()];

    install_linux_preadmission(&controls, &owned, root.path(), facts).unwrap();
    for control in &controls {
        assert!(control.test_linux_preadmission_allows(
            *owned.session_id(),
            authority,
            ProviderCredentialProviderV2::OpenAiBackground
        ));
    }

    let next = [42; 16];
    rebind_linux_preadmission(&controls, *owned.session_id(), next).unwrap();
    clear_linux_preadmission(&controls, *owned.session_id());
    for control in &controls {
        assert!(!control.test_linux_preadmission_allows(
            *owned.session_id(),
            authority,
            ProviderCredentialProviderV2::OpenAiBackground
        ));
        assert!(control.test_linux_preadmission_allows(
            next,
            authority,
            ProviderCredentialProviderV2::OpenAiBackground
        ));
    }
}

#[test]
fn partial_linux_gate_install_rolls_back_only_new_session_gates() {
    let (owned, root, facts) = gate_fixture();
    let authority = *owned.stable().authority_id();
    let (mut primary, _) = test_control();
    let (mut background, _) = test_control();
    Arc::get_mut(&mut primary)
        .unwrap()
        .test_set_runtime_authority(authority);
    Arc::get_mut(&mut background)
        .unwrap()
        .test_set_runtime_authority([99; 16]);
    let controls = [primary.clone(), background];

    assert!(install_linux_preadmission(&controls, &owned, root.path(), facts).is_err());
    assert!(!primary.test_linux_preadmission_allows(
        *owned.session_id(),
        authority,
        ProviderCredentialProviderV2::OpenAiBackground
    ));
}

#[test]
fn failed_idle_gate_rotation_restores_prior_realm_session() {
    let (owned, root, facts) = gate_fixture();
    let authority = *owned.stable().authority_id();
    let (mut primary, _) = test_control();
    let (background, _) = test_control();
    Arc::get_mut(&mut primary)
        .unwrap()
        .test_set_runtime_authority(authority);
    install_linux_preadmission(std::slice::from_ref(&primary), &owned, root.path(), facts).unwrap();

    let result = rebind_linux_preadmission(
        &[primary.clone(), background],
        *owned.session_id(),
        [43; 16],
    );
    assert!(result.is_err());
    assert!(primary.test_linux_preadmission_allows(
        *owned.session_id(),
        authority,
        ProviderCredentialProviderV2::OpenAiBackground
    ));
    assert!(!primary.test_linux_preadmission_allows(
        [43; 16],
        authority,
        ProviderCredentialProviderV2::OpenAiBackground
    ));
}

#[test]
fn failed_active_gate_refresh_clears_mixed_session_facts_and_gates() {
    use crate::application::provider_credential_enrollment::test_http_status_facts_available;

    let (owned, root, facts) = gate_fixture();
    let authority = *owned.stable().authority_id();
    let old_session = *owned.session_id();
    let new_session = [44; 16];
    let (mut primary, _) = test_control();
    let (mut background, _) = test_control();
    Arc::get_mut(&mut primary)
        .unwrap()
        .test_set_runtime_authority(authority);
    Arc::get_mut(&mut background)
        .unwrap()
        .test_set_runtime_authority(authority);
    let controls = [primary.clone(), background.clone()];
    let mut old_facts = ProtectedEnrollmentSessionFacts::for_test();
    old_facts.session = old_session;
    publish(&controls, &old_facts).unwrap();

    // The background realm has no matching old-session preadmission. The
    // primary rebind succeeds first, then fanout must remove that partial gate.
    install_linux_preadmission(std::slice::from_ref(&primary), &owned, root.path(), facts).unwrap();
    let mut next_facts = old_facts;
    next_facts.session = new_session;
    assert!(refresh_linux_session(&controls, old_session, new_session, &next_facts).is_err());

    assert!(!test_http_status_facts_available(&primary, old_session));
    assert!(!test_http_status_facts_available(&background, old_session));
    assert!(!test_http_status_facts_available(&primary, new_session));
    assert!(!test_http_status_facts_available(&background, new_session));
    for control in &controls {
        assert!(!control.test_linux_preadmission_allows(
            old_session,
            authority,
            ProviderCredentialProviderV2::OpenAiBackground
        ));
        assert!(!control.test_linux_preadmission_allows(
            new_session,
            authority,
            ProviderCredentialProviderV2::OpenAiBackground
        ));
    }
}
