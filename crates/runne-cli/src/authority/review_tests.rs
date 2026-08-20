use super::*;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn review() -> AuthorityReviewV1 {
    AuthorityReviewV1 {
        schema_version: "gocode.authority.cli-review/1".into(),
        operation: "sign".into(),
        repository_id: "gocode".into(),
        purpose: Some("V1_PLATFORM_SCOPE_AUTHORIZATION".into()),
        profile: Some("v1-platform-scope".into()),
        subject: Some(ReviewSubject {
            commit_oid: "a".repeat(40),
            object_format: "sha1".into(),
            tree_oid: "b".repeat(40),
        }),
        documents: vec![
            ReviewDocument {
                blob_oid: "c".repeat(40),
                byte_length: 2,
                content_sha256: HEX.into(),
                mode: "100644".into(),
                path: "z.md".into(),
                schema_id: None,
            },
            ReviewDocument {
                blob_oid: "d".repeat(40),
                byte_length: 1,
                content_sha256: "f".repeat(64),
                mode: "100644".into(),
                path: "a.md".into(),
                schema_id: Some("runne.a/1".into()),
            },
        ],
        trust_config_sha256: "1".repeat(64),
        key_id: "2".repeat(64),
        key_fingerprint: "3".repeat(64),
        key_epoch: 1,
        issued_at: Some("2026-08-12T00:00:00Z".into()),
        signing_transcript_sha256: Some("4".repeat(64)),
        output: Some(ReviewOutput {
            artifact_sha256: Some("5".repeat(64)),
            byte_length: Some(9),
            kind: "repository-relative".into(),
            locator: "docs/evidence/receipt.json".into(),
        }),
        rotation: None,
        backup: None,
        continuity: "continuous".into(),
    }
}

#[test]
fn canonical_review_has_sorted_documents_nulls_and_one_lf() {
    let actual = review().canonical_json().expect("valid review");
    let expected = concat!(
        "{\"backup\":null,\"continuity\":\"continuous\",\"documents\":[{\"blob_oid\":\"",
        "dddddddddddddddddddddddddddddddddddddddd\",\"byte_length\":1,\"content_sha256\":\"",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"mode\":\"100644\",\"path\":\"a.md\",\"schema_id\":\"runne.a/1\"},{\"blob_oid\":\"",
        "cccccccccccccccccccccccccccccccccccccccc\",\"byte_length\":2,\"content_sha256\":\"",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"mode\":\"100644\",\"path\":\"z.md\",\"schema_id\":null}],\"issued_at\":\"2026-08-12T00:00:00Z\",\"key_epoch\":1,\"key_fingerprint\":\"",
        "3333333333333333333333333333333333333333333333333333333333333333\",\"key_id\":\"",
        "2222222222222222222222222222222222222222222222222222222222222222\",\"operation\":\"sign\",\"output\":{\"artifact_sha256\":\"",
        "5555555555555555555555555555555555555555555555555555555555555555\",\"byte_length\":9,\"kind\":\"repository-relative\",\"locator\":\"docs/evidence/receipt.json\"},\"profile\":\"v1-platform-scope\",\"purpose\":\"V1_PLATFORM_SCOPE_AUTHORIZATION\",\"repository_id\":\"runne\",\"rotation\":null,\"schema_version\":\"gocode.authority.cli-review/1\",\"signing_transcript_sha256\":\"",
        "4444444444444444444444444444444444444444444444444444444444444444\",\"subject\":{\"commit_oid\":\"",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"object_format\":\"sha1\",\"tree_oid\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"},\"trust_config_sha256\":\"",
        "1111111111111111111111111111111111111111111111111111111111111111\"}\n"
    );
    assert_eq!(actual, expected.as_bytes());
}

#[test]
fn digest_challenge_and_display_bind_the_canonical_review() {
    let review = review();
    assert_eq!(
        review.review_sha256().expect("digest"),
        "a1224980fe4c9d72c3d14efe2e7049e8c106d161bcd4739e3401d558b7d43e28"
    );
    assert_eq!(
        review.confirmation_challenge().expect("challenge"),
        "d558b7d43e28"
    );
    assert_eq!(
        review.public_display().expect("display"),
        concat!(
            "{\"backup\":null,\"continuity\":\"continuous\",\"documents\":[{\"blob_oid\":\"",
            "dddddddddddddddddddddddddddddddddddddddd\",\"byte_length\":1,\"content_sha256\":\"",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"mode\":\"100644\",\"path\":\"a.md\",\"schema_id\":\"runne.a/1\"},{\"blob_oid\":\"",
            "cccccccccccccccccccccccccccccccccccccccc\",\"byte_length\":2,\"content_sha256\":\"",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"mode\":\"100644\",\"path\":\"z.md\",\"schema_id\":null}],\"issued_at\":\"2026-08-12T00:00:00Z\",\"key_epoch\":1,\"key_fingerprint\":\"",
            "3333333333333333333333333333333333333333333333333333333333333333\",\"key_id\":\"",
            "2222222222222222222222222222222222222222222222222222222222222222\",\"operation\":\"sign\",\"output\":{\"artifact_sha256\":\"",
            "5555555555555555555555555555555555555555555555555555555555555555\",\"byte_length\":9,\"kind\":\"repository-relative\",\"locator\":\"docs/evidence/receipt.json\"},\"profile\":\"v1-platform-scope\",\"purpose\":\"V1_PLATFORM_SCOPE_AUTHORIZATION\",\"repository_id\":\"runne\",\"rotation\":null,\"schema_version\":\"gocode.authority.cli-review/1\",\"signing_transcript_sha256\":\"",
            "4444444444444444444444444444444444444444444444444444444444444444\",\"subject\":{\"commit_oid\":\"",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"object_format\":\"sha1\",\"tree_oid\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"},\"trust_config_sha256\":\"",
            "1111111111111111111111111111111111111111111111111111111111111111\"}\n",
            "review_sha256=a1224980fe4c9d72c3d14efe2e7049e8c106d161bcd4739e3401d558b7d43e28\n"
        )
    );
}

#[test]
fn reset_challenge_has_compromise_prefix() {
    let mut review = review();
    review.operation = "trust-reset".into();
    assert_eq!(
        review.confirmation_challenge().expect("challenge"),
        "COMPROMISE-af6a1099f8dd"
    );
}

#[test]
fn digest_changes_when_a_public_field_changes() {
    let review = review();
    let mut changed = review.clone();
    changed.documents[0].byte_length = 3;
    assert_ne!(
        review.review_sha256().expect("digest"),
        changed.review_sha256().expect("digest")
    );
}

#[test]
fn invalid_enum_path_and_digest_are_rejected() {
    let mut invalid = review();
    invalid.operation = "publish".into();
    assert!(invalid.canonical_json().is_err());
    let mut invalid = review();
    invalid.documents[0].path = "/outside".into();
    assert!(invalid.canonical_json().is_err());
    let mut invalid = review();
    invalid.documents[1].schema_id = Some("not-a-schema".into());
    assert!(invalid.canonical_json().is_err());
    let mut invalid = review();
    invalid.trust_config_sha256 = "A".repeat(64);
    assert!(invalid.canonical_json().is_err());
}
