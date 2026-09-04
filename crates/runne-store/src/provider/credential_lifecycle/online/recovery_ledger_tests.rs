const RECOVERY_INSERT: &str = "INSERT INTO credential_cleanup_recovery_attempts
    (operation_id, attempt, installation_owner_id, release_tuple_digest,
     protected_session_digest, database_generation, supervisor_generation,
     lifecycle_revision, credential_fence, continuation_digest, issued_at, expires_at, state)
    SELECT o.operation_id, ?1, ?2, ?3, ?4, ?5, 1,
           h.lifecycle_revision, h.credential_fence, ?6, 100, 150, 'ACCEPTED'
    FROM provider_credential_operations AS o
    JOIN provider_credential_authority_heads AS h ON h.provider_id=o.provider_id
    WHERE o.action='RETIRED_VERSION_CLEANUP'";

fn recovery_ledger_store() -> super::SqliteProviderCredentialLifecycleStore {
    let store = store();
    complete_pair(&store, 10, "first-pair");
    complete_version_two(&store, &CredentialVersionRef::new(provider(), 2).unwrap()).unwrap();
    store
}

fn insert_recovery_ledger(
    connection: &rusqlite::Connection,
    attempt: i64,
    owner: [u8; 32],
    release: [u8; 32],
    generation: i64,
    continuation: [u8; 32],
) -> rusqlite::Result<usize> {
    connection.execute(RECOVERY_INSERT, rusqlite::params![
        attempt, owner, release, [77_u8; 32], generation, continuation,
    ])
}

#[test]
fn recovery_ledger_keeps_one_live_attempt_and_permanent_consumed_binding() {
    let store = recovery_ledger_store();
    let connection = store.connection.lock().unwrap();
    let release = qualified_release(92).digest();
    assert_eq!(insert_recovery_ledger(&connection, 1, [42; 32], release.as_bytes(), 1, [99; 32]).unwrap(), 1);
    assert!(insert_recovery_ledger(&connection, 2, [42; 32], release.as_bytes(), 1, [98; 32]).is_err());
    assert!(connection.execute("UPDATE credential_cleanup_recovery_attempts SET database_generation=2", []).is_err());
    assert!(connection.execute("DELETE FROM credential_cleanup_recovery_attempts", []).is_err());
    assert_eq!(connection.execute(
        "UPDATE credential_cleanup_recovery_attempts SET state='CONSUMED', terminal_digest=continuation_digest", [],
    ).unwrap(), 1);
    assert!(connection.execute("UPDATE credential_cleanup_recovery_attempts SET state='ACCEPTED', terminal_digest=NULL", []).is_err());
    assert!(connection.execute("DELETE FROM credential_cleanup_recovery_attempts", []).is_err());
    assert!(insert_recovery_ledger(&connection, 2, [42; 32], release.as_bytes(), 1, [99; 32]).is_err());
}

#[test]
fn recovery_ledger_rejects_wrong_owner_release_generation_and_unfenced_attachment() {
    let store = recovery_ledger_store();
    let release = qualified_release(92).digest();
    {
        let connection = store.connection.lock().unwrap();
        assert!(insert_recovery_ledger(&connection, 1, [43; 32], release.as_bytes(), 1, [99; 32]).is_err());
        assert!(insert_recovery_ledger(&connection, 1, [42; 32], [93; 32], 1, [99; 32]).is_err());
        assert!(insert_recovery_ledger(&connection, 1, [42; 32], release.as_bytes(), 0, [99; 32]).is_err());
        assert_eq!(connection.query_row("SELECT COUNT(*) FROM credential_cleanup_recovery_attempts", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        connection.execute(
            "INSERT INTO provider_credential_process_attachments
             (operation_id, attachment_attempt, continuation_binding_digest, attached_at, state)
             SELECT operation_id, 1, ?1, 100, 'ATTACHED' FROM provider_credential_operations WHERE action='RETIRED_VERSION_CLEANUP'",
            [[76_u8; 32]],
        ).unwrap();
        assert!(insert_recovery_ledger(&connection, 1, [42; 32], release.as_bytes(), 1, [99; 32]).is_err());
    }
}

#[test]
fn recovery_ledger_rejects_legacy_cleanup_without_consumed_source_binding() {
    let store = store();
    let connection = store.connection.lock().unwrap();
    connection.execute(
        "INSERT INTO provider_credential_authority_heads
         (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version)
         VALUES ('openai', 1, 1, 1, 1)", [],
    ).unwrap();
    connection.execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key,
          expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest,
          begin_proof_expires_at_high_water, qualified_release_tuple_digest, created_at, updated_at)
         VALUES (?1, ?2, 'openai', 'LEGACY_SOURCE_CLEANUP', ?1, 'unlinked-cleanup',
                 1, 1, 'PREPARED', ?3, 200, ?4, 100, 100)",
        rusqlite::params![[70_u8; 16], [42_u8; 32], [71_u8; 32], qualified_release(92).digest().as_bytes()],
    ).unwrap();
    let result = connection.execute(
        &RECOVERY_INSERT.replace("o.action='RETIRED_VERSION_CLEANUP'", "o.action='LEGACY_SOURCE_CLEANUP'"),
        rusqlite::params![1, [42_u8; 32], qualified_release(92).digest().as_bytes(), [77_u8; 32], 1, [99_u8; 32]],
    );
    assert!(result.is_err(), "an unlinked cleanup must not acquire recovery authority");
}

#[test]
fn recovery_ledger_uses_fresh_expiry_for_durable_revoke_after_begin_proof_expires() {
    let store = store();
    complete_pair(&store, 10, "first-pair");
    let revoke = BeginCredentialOperation::new(
        CommandId::from_bytes([81; 16]), IdempotencyKey::new("recover-revoke").unwrap(),
        operation(81), CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider(), CredentialOperationAction::Revoke, None,
        Some(CredentialVersionRef::new(provider(), 1).unwrap()),
        CredentialLifecycleRevision::new(2).unwrap(), CredentialFence::new(2).unwrap(),
        digest(82), 200,
    ).unwrap().with_qualified_release_tuple(qualified_release(92));
    store.begin(revoke).unwrap();
    let connection = store.connection.lock().unwrap();
    let sql = RECOVERY_INSERT
        .replace("o.action='RETIRED_VERSION_CLEANUP'", "o.action='REVOKE'")
        .replace("100, 150", "201, 250");
    assert_eq!(connection.execute(&sql, rusqlite::params![
        1, [42_u8; 32], qualified_release(92).digest().as_bytes(), [77_u8; 32], 1, [99_u8; 32],
    ]).unwrap(), 1);
}
