#[test]
fn v54_adds_encrypted_remote_identity_after_v53() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 53).unwrap();
    assert!(v53_matches(&connection, 53).unwrap());
    apply_migrations_internal(&connection, 54).unwrap();

    assert_eq!(schema_marker(&connection), 54);
    assert!(v42_structure_matches(&connection, true).unwrap(), "v42 inherited");
    assert!(v43_matches(&connection, 54).unwrap(), "v43 inherited");
    assert!(v44_matches(&connection, 54).unwrap(), "v44 inherited");
    assert!(v45_matches(&connection, 54).unwrap(), "v45 inherited");
    assert!(v46_matches(&connection, 54).unwrap(), "v46 inherited");
    assert!(v47_matches(&connection, 54).unwrap(), "v47 inherited");
    assert!(v48_matches(&connection, 54).unwrap(), "v48 inherited");
    assert!(v49_matches(&connection, 54).unwrap(), "v49 inherited");
    assert!(v50_base_matches(&connection, 54).unwrap(), "v50 inherited");
    assert!(v51_base_matches(&connection, 54).unwrap(), "v51 inherited");
    assert!(v52_base_matches(&connection, 54).unwrap(), "v52 inherited");
    assert!(v53_base_matches(&connection, 54).unwrap(), "v53 inherited");
    assert!(v54_matches(&connection, 54).unwrap());
    assert!(classify_existing_connection(&connection).is_ok());
}

#[test]
fn v54_matcher_rejects_missing_append_only_and_upgrade_fence_guards() {
    for trigger in [
        "provider_remote_request_intents_immutable",
        "provider_remote_request_intents_no_delete",
        "provider_remote_response_bindings_immutable",
        "provider_remote_response_bindings_no_delete",
        "schema_v12_fence_provider_remote_request_intents_insert",
        "schema_v12_fence_provider_remote_request_intents_update",
        "schema_v12_fence_provider_remote_request_intents_delete",
        "schema_v12_fence_provider_remote_response_bindings_insert",
        "schema_v12_fence_provider_remote_response_bindings_update",
        "schema_v12_fence_provider_remote_response_bindings_delete",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 54).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v54_matches(&connection, 54).unwrap(), "{trigger}");
        assert!(classify_existing_connection(&connection).is_err(), "{trigger}");
    }
}

#[test]
fn v54_matcher_rejects_orphan_remote_identity_even_without_foreign_key_checks() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 54).unwrap();
    connection.pragma_update(None, "foreign_keys", false).unwrap();
    connection.execute(
        "INSERT INTO provider_remote_response_bindings (
           dispatch_attempt_id,taskrun_id,taskrun_attempt_id,provider_id,profile_id,
           profile_digest,pricing_revision_digest,credential_realm,request_digest,
           runtime_authority_id,database_generation,runtime_generation,fencing_token,
           key_id,key_version,nonce,ciphertext,plaintext_len,plaintext_digest,created_at
         ) VALUES (?1,?2,?3,'provider','profile',?4,?5,'provider',?6,?7,1,1,1,
                   ?8,1,?9,?10,1,?11,0)",
        rusqlite::params![
            [1_u8; 16], [2_u8; 16], [3_u8; 16], [4_u8; 32], [5_u8; 32],
            [6_u8; 32], [7_u8; 16], [8_u8; 16], [9_u8; 12], [10_u8; 17], [11_u8; 32]
        ],
    ).unwrap();

    assert!(!v54_matches(&connection, 54).unwrap());
}
