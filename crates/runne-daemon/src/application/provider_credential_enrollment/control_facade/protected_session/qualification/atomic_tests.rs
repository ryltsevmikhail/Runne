use crate::protected_activation::control_v3::initial_exchange::session_test_support::{
    owned_for_test, session,
};

#[test]
fn qualified_daemon_commits_and_retains_fenced_carrier_but_never_releases_delivery() {
    let (mut session, keys, database) = session(true);
    let command = super::tests::command(runne_api::ProviderCredentialEnrollmentActionV2::Pair);
    session
        .accept_initial_request(
            &super::tests::request(&session, &keys, &command),
            super::tests::now(),
        )
        .unwrap();
    let codec =
        runne_api::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    session
        .begin(
            &codec.encode_desktop_begin(&command, 1).unwrap(),
            super::tests::now(),
        )
        .unwrap();
    let installed = session.take_installed_facts().unwrap();
    let mut verifier =
        runne_native_qualification::QualificationAdmissionVerifier::test_only_from_verifying_keys(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key(),
        );
    let continuation = runne_provider::CredentialBindingDigest::from_measured([31; 32]).unwrap();
    let pending = session
        .commit_qualification(
            &owned_for_test(),
            &installed,
            continuation,
            &mut verifier,
            super::tests::now() / 1000,
        )
        .unwrap();
    session
        .accept_qualification_fence(pending, &owned_for_test(), super::tests::now() / 1000)
        .unwrap();
    assert!(session.qualification.is_none());
    assert!(session.qualification_fenced.is_some());
    assert!(session.take_ticket_authority().is_err());
    assert!(
        session
            .commit_qualification(
                &owned_for_test(),
                &installed,
                continuation,
                &mut verifier,
                super::tests::now() / 1000
            )
            .is_err()
    );
    assert_eq!(
        super::tests::rows(&database, "provider_qualification_admission_fences"),
        1
    );
    assert_eq!(
        super::tests::rows(&database, "provider_credential_ticket_attempts"),
        1
    );
    let qualified = session
        .qualification_fenced
        .take()
        .unwrap()
        .into_writer_delivery()
        .unwrap()
        .into_writer_exchange()
        .unwrap();
    assert_eq!(qualified.receipt().ticket_attempt().get(), 1);
}

#[test]
fn qualified_retention_detects_current_session_rotation_before_consuming_admission() {
    let (mut session, _, _) = session(true);
    let owned = owned_for_test();
    session.facts.database_generation += 1;
    assert!(session.qualification_snapshot_matches(&owned).is_err());
    assert!(session.qualification.is_some());
}

fn committed_for_rejection() -> (
    super::DaemonProtectedCredentialEnrollmentSession,
    super::CommittedQualification,
) {
    let (mut session, keys, _directory) = session(true);
    let command = super::tests::command(runne_api::ProviderCredentialEnrollmentActionV2::Pair);
    session
        .accept_initial_request(
            &super::tests::request(&session, &keys, &command),
            super::tests::now(),
        )
        .unwrap();
    let codec =
        runne_api::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    session
        .begin(
            &codec.encode_desktop_begin(&command, 1).unwrap(),
            super::tests::now(),
        )
        .unwrap();
    let installed = session.take_installed_facts().unwrap();
    let mut verifier =
        runne_native_qualification::QualificationAdmissionVerifier::test_only_from_verifying_keys(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key(),
        );
    let continuation = runne_provider::CredentialBindingDigest::from_measured([31; 32]).unwrap();
    let pending = session
        .commit_qualification(
            &owned_for_test(),
            &installed,
            continuation,
            &mut verifier,
            super::tests::now() / 1000,
        )
        .unwrap();
    (session, pending)
}

#[test]
fn qualified_consuming_transition_rejects_fingerprint_continuation_foreign_receipt_and_delay() {
    for fault in 0..5 {
        let (mut session, mut committed) = committed_for_rejection();
        let mut now = super::tests::now() / 1000;
        match fault {
            0 => committed.fingerprint[0] ^= 1,
            1 => {
                committed.continuation =
                    runne_provider::CredentialBindingDigest::from_measured([32; 32]).unwrap()
            }
            2 => committed.receipt = committed_for_rejection().1.receipt,
            3 => now = u64::try_from(committed.receipt.effective_expires_at()).unwrap(),
            4 => now = u64::try_from(committed.receipt.committed_at() - 1).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            session
                .accept_qualification_fence(committed, &owned_for_test(), now)
                .is_err()
        );
        assert!(session.qualification_fenced.is_none());
        assert!(session.take_ticket_authority().is_err());
    }
}

#[test]
fn qualified_current_session_release_and_each_generation_rotation_reject_after_commit() {
    for fault in 0..7 {
        let (mut session, committed) = committed_for_rejection();
        match fault {
            0 => session.facts.session[0] ^= 1,
            1 => session.facts.release[0] ^= 1,
            2 => session.facts.runtime_authority[0] ^= 1,
            3 => session.facts.database_generation += 1,
            4 => session.facts.launch_generation += 1,
            5 => session.facts.supervisor_generation += 1,
            6 => session.facts.launch_authority[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            session
                .accept_qualification_fence(
                    committed,
                    &owned_for_test(),
                    super::tests::now() / 1000
                )
                .is_err()
        );
        assert!(session.take_ticket_authority().is_err());
    }
}
