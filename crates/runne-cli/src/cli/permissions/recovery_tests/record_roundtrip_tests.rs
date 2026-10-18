use super::*;

#[test]
fn immutable_record_roundtrips_and_binds_all_request_fields() {
    let input = intent();
    let record = decode_recovery_record(&saved_record(&input)).unwrap();
    assert_eq!(record.command_id, input.command_id);
    assert_eq!(record.scope_digest, scope_digest(&record.stable_runtime));
    assert_eq!(
        record.intent_digest,
        local_intent_digest(&input, &record.stable_runtime)
    );
    let mut changed = input.clone();
    changed.idempotency_key.push('x');
    assert_ne!(
        local_intent_digest(&input, &record.stable_runtime),
        local_intent_digest(&changed, &record.stable_runtime)
    );
    changed = input.clone();
    changed.expected_authorization_revision += 1;
    assert_ne!(
        local_intent_digest(&input, &record.stable_runtime),
        local_intent_digest(&changed, &record.stable_runtime)
    );
    changed = input.clone();
    changed.expires_at_unix_ms = Some(1_800_000_000_000);
    assert_ne!(
        local_intent_digest(&input, &record.stable_runtime),
        local_intent_digest(&changed, &record.stable_runtime)
    );
}

#[test]
fn epoch_zero_mode_record_roundtrips_and_zero_generation_stays_corrupt() {
    let input = intent();
    let mut session = session_info();
    session.authorization_epoch = 0;
    let bytes = make_recovery_record(
        &input,
        StableRuntimeIdentity::from_session(&session).unwrap(),
        RuntimeAuditSnapshot::from_session(&session).unwrap(),
    )
    .unwrap();
    assert_eq!(
        decode_recovery_record(&bytes)
            .unwrap()
            .audit
            .authorization_epoch,
        0
    );

    let mut generation_zero = session;
    generation_zero.launch_generation = 0;
    assert!(RuntimeAuditSnapshot::from_session(&generation_zero).is_err());

    let mut malformed: serde_json::Value = serde_json::from_slice(&saved_record(&input)).unwrap();
    malformed["audit"]["launchGeneration"] = serde_json::json!(0);
    assert!(matches!(
        decode_recovery_record(&serde_json::to_vec(&malformed).unwrap()),
        Err(RecoveryError::Corrupt)
    ));
}

#[test]
fn authority_id_uses_exact_lowercase_32_character_hex_identity() {
    let valid = session_info();
    let stable = StableRuntimeIdentity::from_session(&valid).unwrap();
    assert_eq!(stable.authority_id, valid.authority_id);
    for invalid in [
        "018f2e3a-7000-7000-8000-000000000003",
        "018F2E3A700070008000000000000003",
        "018f2e3a70007000800000000000000g",
        "018f2e3a70007000800000000000003",
        "018f2e3a7000700080000000000000030",
    ] {
        let mut session = valid.clone();
        session.authority_id = invalid.to_owned();
        assert!(StableRuntimeIdentity::from_session(&session).is_err());
    }
}
