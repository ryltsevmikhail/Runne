use super::*;

#[test]
fn legacy_cleanup_recovery_after_rotation_and_begin_expiry_claims_current_lease() {
    recovered_claim(false);
}

#[test]
fn legacy_cleanup_recovery_after_rotation_rejects_foreign_session_without_consuming() {
    recovered_claim(true);
}

fn recovered_claim(foreign_session: bool) {
    let mut store = store();
    let cleanup = complete_import(&store);
    rotate_after_import(&store);
    store.now = std::sync::Arc::new(|| 301);
    let authority = super::super::super::online_claim_test_support::measurements_for(&store);
    let request = runne_provider::CredentialCleanupRecoveryRequest::new(
        cleanup,
        CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        authority
            .release_manifest_digest(qualified_release(92).digest().as_bytes())
            .unwrap(),
        authority.protected_session_id([77; 32]).unwrap(),
        authority.desktop_supervisor_generation(1).unwrap(),
        1,
        CredentialLifecycleRevision::new(3).unwrap(),
        CredentialFence::new(3).unwrap(),
        authority.continuation_binding_digest([99; 32]).unwrap(),
        30,
    );
    let accepted = store.accept_cleanup_recovery(request).unwrap();
    store.attach_cleanup_recovery(accepted).unwrap();
    let issued = store
        .issue_ticket_attempt(
            runne_provider::IssueCredentialTicketDigest::new(cleanup, digest(18), digest(99), 100)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(issued.expires_at_high_water(), 331);
    let claim = super::super::super::online_claim_test_support::seal_claim_with_context(
        &store,
        ClaimCredentialOperation::new(issued, digest(18), digest(99), digest(20), 1, 1).unwrap(),
        qualified_release(92).digest().as_bytes(),
        [if foreign_session { 78 } else { 77 }; 32],
    );
    if foreign_session {
        assert!(store.claim(claim).is_err());
    } else {
        store.claim(claim).unwrap();
    }
    let ledger: (String, i64, i64) = store.connection.lock().unwrap().query_row(
        "SELECT state, lifecycle_revision, credential_fence FROM credential_cleanup_recovery_attempts
         WHERE operation_id=?1", [cleanup.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    assert_eq!(
        ledger,
        (
            if foreign_session {
                "ACCEPTED"
            } else {
                "CONSUMED"
            }
            .into(),
            3,
            3
        )
    );
    assert_eq!(
        store
            .load_operation(cleanup)
            .unwrap()
            .lifecycle_revision()
            .get(),
        2
    );
}
