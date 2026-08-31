#[test]
fn verification_lease_persists_exact_active_ref_and_rejects_corruption() {
    let connection = v24_connection();
    insert_head_for_test(&connection, "verification-ref");
    insert_allocated_operation(&connection, 7, "verification-ref", 1, 1, Some(1)).unwrap();
    readback_verified_operation(&connection, 7);
    connection
        .execute(
            "UPDATE provider_credential_authority_heads
             SET lifecycle_revision=2, credential_fence=2, readiness_revision=2,
                 active_credential_version=1, active_ref_digest=?1, observed_at_high_water=1
             WHERE provider_id='verification-ref'",
            [[7_u8; 32]],
        )
        .unwrap();
    let insert = "INSERT INTO provider_credential_verification_observations
        (observation_id, provider_id, verification_kind, lifecycle_revision,
         credential_fence, active_credential_version, active_ref_digest, state, result,
         intent_proof_digest, proof_consumed, verifier_revision, started_at,
         expires_at_high_water, observed_at)
         VALUES (?1, 'verification-ref', 'LOCAL', 2, 2, 1, ?2, 'LEASED', NULL,
                 ?3, 1, 1, 1, 3, NULL)";
    connection
        .execute(insert, rusqlite::params![[8_u8; 16], [7_u8; 32], [8_u8; 32]])
        .unwrap();
    assert!(connection
        .execute(
            "INSERT INTO provider_credential_verification_observations
             (observation_id, provider_id, verification_kind, lifecycle_revision,
              credential_fence, state, result, intent_proof_digest, proof_consumed,
              verifier_revision, started_at, expires_at_high_water, observed_at)
             VALUES (?1, 'verification-ref', 'LOCAL', 2, 2, 'LEASED', NULL, ?2, 1, 1,
                     1, 3, NULL)",
            rusqlite::params![[10_u8; 16], [10_u8; 32]],
        )
        .is_err());
    for (observation, digest) in [
        (11_u8, rusqlite::types::Value::Blob(vec![0; 32])),
        (12, rusqlite::types::Value::Blob(vec![7; 31])),
        (13, rusqlite::types::Value::Text("digest-text".into())),
    ] {
        assert!(connection
            .execute(
                insert,
                rusqlite::params![[observation; 16], digest, [observation; 32]],
            )
            .is_err());
    }
    assert!(connection
        .execute(
            "UPDATE provider_credential_verification_observations
             SET active_ref_digest=?1 WHERE observation_id=?2",
            rusqlite::params![[9_u8; 32], [8_u8; 16]],
        )
        .is_err());
    assert!(connection
        .execute(
            insert,
            rusqlite::params![[9_u8; 16], [9_u8; 32], [10_u8; 32]],
        )
        .is_err());
}
