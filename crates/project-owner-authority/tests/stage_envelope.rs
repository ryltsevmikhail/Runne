use gocode_project_owner_authority::{
    STAGE_ENVELOPE_SCHEMA_V1, StageAuthorityEnvelopeV1, canonical_checked_in_stage_envelope,
    canonical_stage_payload, canonical_unsigned_stage_envelope,
};

#[test]
fn stage_envelope_canonical_bytes_bind_the_payload_without_an_envelope_hash_field() {
    let envelope = StageAuthorityEnvelopeV1 {
        schema_version: STAGE_ENVELOPE_SCHEMA_V1.into(),
        repository_id: "gocode".into(),
        bootstrap_receipt_sha256: [1; 32],
        issuer_role: "RC1_QUALIFICATION_AUTHORIZER".into(),
        issuer_principal_id: "principal-1".into(),
        issuer_controlling_account_id: "account-1".into(),
        issuer_lane_id: "lane-1".into(),
        issuer_key_id: "2".repeat(64),
        issuer_key_epoch: 1,
        signature_profile_id: "profile-1".into(),
        payload_schema_id: "gocode.release.rc1-qualification-decision/1".into(),
        payload_schema_sha256: [3; 32],
        payload_sha256: [4; 32],
        payload: serde_json::json!({"schema_version":"gocode.release.rc1-qualification-decision/1"}),
        issued_at: "2026-08-13T00:00:01Z".into(),
        not_before: "2026-08-13T00:00:02Z".into(),
        expires_at: "2026-08-13T00:00:03Z".into(),
        revocation_epoch: 1,
        authorization_nonce: "nonce-1".into(),
    };
    let canonical = canonical_unsigned_stage_envelope(&envelope).unwrap();
    assert!(!canonical.ends_with(b"\n"));
    let checked_in = canonical_checked_in_stage_envelope(&envelope, &[7; 64]).unwrap();
    assert!(checked_in.ends_with(b"\n"));
    assert!(!checked_in[..checked_in.len() - 1].ends_with(b"\n"));
    assert!(
        !canonical
            .windows(b"envelope_sha256".len())
            .any(|part| part == b"envelope_sha256")
    );
}

#[test]
fn stage_payload_canonicalizes_nested_object_order_and_rejects_enclosing_hashes() {
    let left = serde_json::json!({"z":{"b":2,"a":1},"a":[{"y":2,"x":1}]});
    let right = serde_json::json!({"a":[{"x":1,"y":2}],"z":{"a":1,"b":2}});
    assert_eq!(
        canonical_stage_payload(&left).unwrap(),
        canonical_stage_payload(&right).unwrap()
    );
    assert!(
        canonical_stage_payload(&serde_json::json!({"nested":{"stage_envelope_sha256":"0"}}))
            .is_err()
    );
}
