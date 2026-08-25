use serde_json::{Value, json};

use super::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialOperationIdV2, ProviderCredentialProviderV2,
    ProviderCredentialSafeSnapshotV2, ProviderCredentialVerificationKindV2,
    VerifyProviderCredential,
};

mod host;

const FORBIDDEN_KEYS: [&str; 7] = [
    "credential",
    "ticket",
    "secret",
    "path",
    "versionRef",
    "releaseDigest",
    "nativeError",
];

#[test]
fn provider_credential_enrollment_wire_is_metadata_only_and_closed() {
    let input = begin_json();
    let command: BeginProviderCredentialEnrollment =
        serde_json::from_value(input.clone()).expect("approved metadata-only command");
    let encoded = serde_json::to_value(command).expect("safe command serialization");

    assert_safe_keys(&encoded);
    assert_exact_keys(
        &encoded,
        &[
            "action",
            "provider",
            "expectedLifecycleRevision",
            "commandIdentity",
            "idempotencyKey",
            "nativeIntentId",
        ],
    );
    for forbidden in FORBIDDEN_KEYS {
        let mut substituted = input.clone();
        substituted
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), Value::String("forbidden".to_owned()));
        assert!(serde_json::from_value::<BeginProviderCredentialEnrollment>(substituted).is_err());
    }
}

#[test]
fn provider_credential_enrollment_begin_rejects_invalid_bounds_and_internal_actions() {
    for (field, value) in [
        ("expectedLifecycleRevision", json!(0)),
        ("commandIdentity", json!("")),
        ("idempotencyKey", json!("bad\nkey")),
        ("nativeIntentId", json!("x".repeat(257))),
        ("action", json!("retired_version_cleanup")),
        ("action", json!("writer_identity_migration_effect")),
    ] {
        let mut input = begin_json();
        input
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), value);
        assert!(
            serde_json::from_value::<BeginProviderCredentialEnrollment>(input).is_err(),
            "invalid {field} must be rejected"
        );
    }
}

#[test]
fn provider_credential_verify_and_safe_snapshot_use_only_approved_metadata() {
    let verify: VerifyProviderCredential =
        serde_json::from_value(verify_json()).expect("approved verification command");
    let snapshot: ProviderCredentialSafeSnapshotV2 = serde_json::from_value(json!({
        "providerId": "openai",
        "credentialState": "configured",
        "readiness": "ready",
        "lifecycleRevision": 7,
        "readinessRevision": 9,
        "observedAt": 100,
        "verificationState": "local_verified",
        "verificationRevision": 3,
        "pendingOperation": null,
        "cleanupPending": false,
        "lastDisposition": "completed"
    }))
    .expect("approved safe snapshot");

    assert_eq!(snapshot.provider_id(), ProviderCredentialProviderV2::OpenAi);
    assert_eq!(snapshot.lifecycle_revision(), 7);
    assert_eq!(snapshot.readiness_revision(), 9);
    let verify = serde_json::to_value(verify).unwrap();
    let snapshot = serde_json::to_value(snapshot).unwrap();
    assert_safe_keys(&verify);
    assert_safe_keys(&snapshot);
    assert_exact_keys(
        &verify,
        &[
            "provider",
            "expectedLifecycleRevision",
            "verificationKind",
            "commandIdentity",
            "nativeIntentId",
        ],
    );
    assert_exact_keys(
        &snapshot,
        &[
            "providerId",
            "credentialState",
            "readiness",
            "lifecycleRevision",
            "readinessRevision",
            "observedAt",
            "verificationState",
            "verificationRevision",
            "pendingOperation",
            "cleanupPending",
            "lastDisposition",
        ],
    );
}

#[test]
fn provider_credential_external_dtos_reject_unknown_fields() {
    let mut verify = verify_json();
    verify
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), json!(true));
    assert!(serde_json::from_value::<VerifyProviderCredential>(verify).is_err());

    let mut snapshot = safe_snapshot_json();
    snapshot
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), json!(true));
    assert!(serde_json::from_value::<ProviderCredentialSafeSnapshotV2>(snapshot).is_err());
}

#[test]
fn provider_credential_resume_identity_is_exact_nonzero_lower_hex() {
    assert!(
        serde_json::from_str::<ProviderCredentialOperationIdV2>(
            "\"0102030405060708090a0b0c0d0e0f10\""
        )
        .is_ok()
    );
    for invalid in [
        "\"\"",
        "\"00000000000000000000000000000000\"",
        "\"0102030405060708090A0B0C0D0E0F10\"",
        "\"0102\"",
    ] {
        assert!(serde_json::from_str::<ProviderCredentialOperationIdV2>(invalid).is_err());
    }
}

#[test]
fn provider_credential_safe_snapshot_rejects_invalid_revision_and_time_bounds() {
    for (field, value) in [
        ("lifecycleRevision", json!(0)),
        ("readinessRevision", json!(0)),
        ("observedAt", json!(-1)),
        ("verificationRevision", json!(0)),
    ] {
        let mut snapshot = safe_snapshot_json();
        snapshot
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), value);
        assert!(
            serde_json::from_value::<ProviderCredentialSafeSnapshotV2>(snapshot).is_err(),
            "invalid {field} must be rejected"
        );
    }
}

#[test]
fn provider_credential_commands_have_validated_safe_constructors_and_getters() {
    let begin = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "018f0c4e-7b9a-7cc2-8f0a-123456789abc",
        "pair-openai-7",
        "intent-openai-7",
    )
    .unwrap();
    assert_eq!(begin.action(), ProviderCredentialEnrollmentActionV2::Pair);
    assert_eq!(begin.provider(), ProviderCredentialProviderV2::OpenAi);
    assert_eq!(begin.expected_lifecycle_revision(), 7);
    assert_eq!(begin.idempotency_key(), "pair-openai-7");
    assert!(
        BeginProviderCredentialEnrollment::new(
            ProviderCredentialEnrollmentActionV2::Revoke,
            ProviderCredentialProviderV2::OpenAi,
            0,
            "018f0c4e-7b9a-7cc2-8f0a-123456789abc",
            "revoke-openai",
            "intent-revoke",
        )
        .is_err()
    );
}

#[test]
fn provider_credential_verify_has_validated_safe_constructor() {
    let verify = VerifyProviderCredential::new(
        ProviderCredentialProviderV2::OpenAi,
        7,
        ProviderCredentialVerificationKindV2::Remote,
        "018f0c4e-7b9a-7cc2-8f0a-123456789abc",
        "verify-openai-7",
    )
    .unwrap();
    assert_eq!(verify.provider(), ProviderCredentialProviderV2::OpenAi);
    assert_eq!(
        verify.verification_kind(),
        ProviderCredentialVerificationKindV2::Remote
    );
    assert_eq!(verify.expected_lifecycle_revision(), 7);
}

fn begin_json() -> Value {
    json!({
        "action": "pair",
        "provider": "openai",
        "expectedLifecycleRevision": 7,
        "commandIdentity": "018f0c4e-7b9a-7cc2-8f0a-123456789abc",
        "idempotencyKey": "pair-openai-7",
        "nativeIntentId": "intent-openai-7"
    })
}

fn safe_snapshot_json() -> Value {
    json!({
        "providerId": "openai",
        "credentialState": "configured",
        "readiness": "ready",
        "lifecycleRevision": 7,
        "readinessRevision": 9,
        "observedAt": 100,
        "verificationState": "local_verified",
        "verificationRevision": 3,
        "pendingOperation": null,
        "cleanupPending": false,
        "lastDisposition": "completed"
    })
}

fn verify_json() -> Value {
    json!({
        "provider": "openai",
        "expectedLifecycleRevision": 7,
        "verificationKind": "local",
        "commandIdentity": "018f0c4e-7b9a-7cc2-8f0a-123456789abc",
        "nativeIntentId": "verify-openai-7"
    })
}

fn assert_safe_keys(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                assert!(
                    !FORBIDDEN_KEYS.contains(&key.as_str()),
                    "forbidden key: {key}"
                );
                assert_safe_keys(value);
            }
        }
        Value::Array(values) => values.iter().for_each(assert_safe_keys),
        _ => {}
    }
}

fn assert_exact_keys(value: &Value, expected: &[&str]) {
    let object = value.as_object().expect("V2 DTO serializes as an object");
    let actual = object
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
}
