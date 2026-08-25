use runne_api::{ProviderReadinessStatusV1, ProviderStatusSnapshotV1};

#[test]
fn provider_status_accepts_only_bounded_non_secret_metadata() {
    let value = ProviderStatusSnapshotV1::new(
        "openai",
        "openai_responses_text_v1",
        "openai-responses-text-v1",
        [0x11; 32],
        ProviderReadinessStatusV1::Ready,
        true,
    )
    .expect("valid provider status");

    assert_eq!(value.provider_id(), "openai");
    assert_eq!(value.readiness(), ProviderReadinessStatusV1::Ready);
    assert!(value.selected());
}

#[test]
fn provider_status_rejects_invalid_digest_and_control_metadata() {
    let invalid_digest = serde_json::from_str::<ProviderStatusSnapshotV1>(
        r#"{
            "providerId":"openai",
            "mode":"openai_responses_text_v1",
            "profileId":"openai-responses-text-v1",
            "profileDigest":"profile",
            "readiness":"ready",
            "selected":true
        }"#,
    )
    .expect("serde shape");
    assert!(invalid_digest.validate().is_err());
    assert!(
        ProviderStatusSnapshotV1::new(
            "openai\nsecret",
            "openai_responses_text_v1",
            "openai-responses-text-v1",
            [0x11; 32],
            ProviderReadinessStatusV1::Ready,
            true,
        )
        .is_err()
    );
}

#[test]
fn provider_status_wire_is_strict_and_closed() {
    let unknown = r#"{
        "providerId":"openai",
        "mode":"openai_responses_text_v1",
        "profileId":"openai-responses-text-v1",
        "profileDigest":"1111111111111111111111111111111111111111111111111111111111111111",
        "readiness":"future",
        "selected":true,
        "credential":"secret"
    }"#;
    assert!(serde_json::from_str::<ProviderStatusSnapshotV1>(unknown).is_err());
}
