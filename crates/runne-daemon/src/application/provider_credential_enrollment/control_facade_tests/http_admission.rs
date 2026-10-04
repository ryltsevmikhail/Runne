use std::sync::Arc;

use runne_api::{ProviderCredentialEnrollmentHostError, ProviderCredentialProviderV2};
use runne_http::ProviderCredentialEnrollmentHttpAdmissionResolver;

use super::super::test_modules::protected_session_tests::{control, id};
use crate::application::provider_credential_enrollment::{
    DaemonProviderCredentialEnrollmentControl, ProtectedEnrollmentSessionFacts,
};

type Resolver = crate::application::provider_credential_enrollment::http_admission_resolver::LiveCredentialHttpAdmissionResolver;

fn resolver(control: &Arc<DaemonProviderCredentialEnrollmentControl>) -> Resolver {
    Resolver::new(
        control.http_authority_issuer.clone(),
        Arc::clone(&control.http_facts),
    )
}

pub(crate) fn test_http_status_facts_available(
    control: &Arc<DaemonProviderCredentialEnrollmentControl>,
    session: [u8; 16],
) -> bool {
    resolver(control)
        .resolve_status(session, &ProviderCredentialProviderV2::DeepSeek)
        .is_ok()
}

fn assert_status_error(
    resolver: &Resolver,
    session: [u8; 16],
    expected: ProviderCredentialEnrollmentHostError,
) {
    assert!(matches!(
        resolver.resolve_status(session, &ProviderCredentialProviderV2::DeepSeek),
        Err(error) if error == expected
    ));
}

#[test]
fn http_status_resolver_denies_cold_wrong_and_revoked_sessions() {
    let (control, _) = control();
    let facts = ProtectedEnrollmentSessionFacts::for_test();
    let resolver = resolver(&control);
    assert_status_error(
        &resolver,
        id(2),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );
    control.publish_http_facts(facts).unwrap();
    assert_status_error(
        &resolver,
        id(3),
        ProviderCredentialEnrollmentHostError::AccessDenied,
    );
    assert!(
        resolver
            .resolve_status(id(2), &ProviderCredentialProviderV2::DeepSeek)
            .is_ok()
    );
    control.clear_http_facts(id(2));
    assert_status_error(
        &resolver,
        id(2),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );
}

#[test]
fn protected_session_drop_revokes_its_current_http_facts() {
    let (control, keys) = control();
    let facts = ProtectedEnrollmentSessionFacts::for_test();
    control.publish_http_facts(facts.clone()).unwrap();
    let rendezvous =
        crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let session = control
        .start_test_protected_session(&keys, facts, rendezvous)
        .unwrap();
    drop(session);
    assert_status_error(
        &resolver(&control),
        id(2),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );
}

#[test]
fn renewal_then_next_round_keeps_replacement_http_facts_until_its_drop() {
    let (control, keys) = control();
    let facts_a = ProtectedEnrollmentSessionFacts::for_test();
    let mut session_a = control
        .start_test_protected_session(
            &keys,
            facts_a.clone(),
            crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
        )
        .unwrap();
    control.publish_http_facts(facts_a).unwrap();

    let facts_b = ProtectedEnrollmentSessionFacts::for_test_with_session(id(4));
    session_a.refresh_test_http_facts(facts_b.clone()).unwrap();
    session_a.clear_http_facts();
    drop(session_a);
    assert_status_error(
        &resolver(&control),
        id(4),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );

    let session_b = control
        .start_test_protected_session(
            &keys,
            facts_b.clone(),
            crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
        )
        .unwrap();
    control.publish_http_facts(facts_b).unwrap();
    assert!(
        resolver(&control)
            .resolve_status(id(4), &ProviderCredentialProviderV2::DeepSeek)
            .is_ok()
    );
    drop(session_b);
    assert_status_error(
        &resolver(&control),
        id(4),
        ProviderCredentialEnrollmentHostError::Unavailable,
    );
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[test]
fn linux_http_status_requires_live_signed_transition_and_approval() {
    use runne_api::provider_credential_enrollment::linux_activation_policy::{
        ACTIVATION_RECORD_FILE, LinuxEnrollmentActivationRecord, LinuxEnrollmentScope,
        LinuxInstallationFacts,
    };
    use std::os::unix::fs::PermissionsExt as _;

    let (mut control, _) = control();
    let (owned, _, _) = crate::protected_activation::test_enrollment_owned_and_sessions();
    let runtime_authority = *owned.stable().authority_id();
    std::sync::Arc::get_mut(&mut control)
        .unwrap()
        .runtime_authority = runtime_authority;
    let facts = ProtectedEnrollmentSessionFacts::from_owned(&owned, runtime_authority, 10).unwrap();
    control.publish_http_facts(facts.clone()).unwrap();
    let (session, installation, release, binding, supervisor, peer, database, daemon) =
        facts.http_authority_parts();
    let authority = control
        .http_authority_issuer
        .issue_base(
            installation,
            release,
            binding,
            supervisor,
            daemon,
            database,
            peer,
        )
        .unwrap();
    let provider = ProviderCredentialProviderV2::DeepSeek;
    let status =
        || control.status_http(&control.http_authority_verifier, &authority, provider, 100);
    assert!(
        status().is_err(),
        "uninstalled transition gate denies status"
    );

    let root = tempfile::tempdir().unwrap();
    let installation_facts = LinuxInstallationFacts {
        runtime_root_digest: [21; 32],
        desktop_image_digest: [22; 32],
        writer_image_digest: [23; 32],
        daemon_image_digest: [24; 32],
        runtime_authority_id: runtime_authority,
        machine_id_digest: [25; 32],
    };
    control
        .install_linux_preadmission(&owned, root.path(), installation_facts)
        .unwrap();
    assert!(status().is_err(), "missing approval denies status");

    let record = LinuxEnrollmentActivationRecord {
        provider_scope: LinuxEnrollmentScope::Catalog,
        runtime_root_digest: installation_facts.runtime_root_digest,
        desktop_image_digest: installation_facts.desktop_image_digest,
        writer_image_digest: installation_facts.writer_image_digest,
        daemon_image_digest: installation_facts.daemon_image_digest,
        runtime_authority_id: installation_facts.runtime_authority_id,
        machine_id_digest: installation_facts.machine_id_digest,
        approved_at_unix_millis: 1,
    };
    let path = root.path().join(ACTIVATION_RECORD_FILE);
    std::fs::write(&path, record.to_config_json()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        status().is_ok(),
        "verified V3 facts and live approval admit status"
    );

    std::fs::remove_file(&path).unwrap();
    assert!(status().is_err(), "revoked approval denies status");
    control
        .rebind_linux_preadmission(session, [31; 16])
        .unwrap();
    assert!(status().is_err(), "stale signed session denies status");
}
