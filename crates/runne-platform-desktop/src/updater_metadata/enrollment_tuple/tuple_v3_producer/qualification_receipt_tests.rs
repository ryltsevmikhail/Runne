//! Receipt tests for the qualified tuple V3 producer.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::enrollment_tuple_v3_producer::{produce_qualified_with_observer, produce_with_observer};
use super::enrollment_tuple_v3_producer_tests::{FixedObserver, Fixture};
use runne_api::NativeEnrollmentTupleV3;

fn commit() -> String {
    "1".repeat(40)
}

fn candidate() -> String {
    hex::encode(Sha256::digest(commit().as_bytes()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn measured(fixture: &Fixture) -> serde_json::Value {
    let tuple = produce_with_observer(&fixture.app, &fixture.target, &FixedObserver).unwrap();
    serde_json::to_value(tuple).unwrap()["digests"].clone()
}

fn receipt_value(fixture: &Fixture, qualified_at: u64, expires_at: u64) -> serde_json::Value {
    let digests = measured(fixture);
    serde_json::json!({
        "schemaVersion": 1,
        "platform": "macos",
        "architecture": "arm64",
        "sourceCommit": commit(),
        "releaseCandidateSha256": candidate(),
        "artifactSha256": fixture.target.artifact_sha256,
        "desktopSha256": digests["desktopSha256"],
        "writerSha256": digests["writerSha256"],
        "daemonSha256": digests["daemonSha256"],
        "credentialServiceSha256": digests["credentialServiceSha256"],
        "launchAgentPlistSha256": digests["launchAgentPlistSha256"],
        "entitlementsSha256": digests["entitlementsSha256"],
        "provisioningSha256": digests["provisioningSha256"],
        "xpcProtocolSha256": digests["xpcProtocolSha256"],
        "contractSha256": digests["contractSha256"],
        "checks": ["updater-metadata-tests", "codesign-bundle-strict", "bundle-component-digests"],
        "checkCommands": [
            "cargo test -p runne-platform-desktop --lib updater_metadata",
            "codesign --verify --strict --verbose=2 Runne.app",
            "bundle component sha256 match against the measured tuple inputs",
        ],
        "checkExitStatuses": [0, 0, 0],
        "checkLogSha256": "2".repeat(64),
        "qualifiedAtUnixSeconds": qualified_at,
        "expiresAtUnixSeconds": expires_at,
    })
}

/// Rewrites the staged binding and target so the candidate is one commit
/// digest and the target outlives a qualification row.
fn prepared() -> Fixture {
    let mut fixture = Fixture::exact();
    let target = fixture.target.clone();
    let binding = format!(
        "{{\"arch\":\"{}\",\"platform\":\"{}\",\"productId\":\"{}\",\"profileId\":\"{}\",\"releaseCandidateSha256\":\"{}\",\"schemaVersion\":1,\"version\":\"{}\"}}",
        target.arch,
        target.platform,
        target.product_id,
        target.profile_id,
        candidate(),
        target.version,
    );
    std::fs::write(
        fixture
            .app
            .join("Contents/Resources/native-enrollment/release-candidate-binding.json"),
        binding,
    )
    .unwrap();
    fixture.target.release_candidate_sha256 = candidate();
    fixture.target.expires_at_unix_seconds = now() + 1_000;
    fixture
}

fn write_receipt(fixture: &Fixture, value: &serde_json::Value) -> PathBuf {
    let path = fixture.app.join("receipt.json");
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

fn qualified(
    fixture: &Fixture,
    receipt: &Path,
    qualified_at: u64,
    expires_at: u64,
) -> Result<NativeEnrollmentTupleV3, ()> {
    produce_qualified_with_observer(
        &fixture.app,
        &fixture.target,
        receipt,
        qualified_at,
        expires_at,
        &FixedObserver,
    )
    .map_err(|_| ())
}

#[test]
fn exact_receipt_attaches_a_bound_qualification_row() {
    let fixture = prepared();
    let (qualified_at, expires_at) = (now() - 100, now() + 800);
    let value = receipt_value(&fixture, qualified_at, expires_at);
    let receipt = write_receipt(&fixture, &value);
    let tuple = qualified(&fixture, &receipt, qualified_at, expires_at).expect("exact receipt");
    let encoded = serde_json::to_value(&tuple).unwrap();
    let row = &encoded["nativeEnrollmentQualification"];
    assert_eq!(row["platform"], "macos");
    assert_eq!(row["architecture"], "arm64");
    assert_eq!(row["packageKind"], "dmg");
    assert_eq!(row["qualifiedAtUnixSeconds"], qualified_at);
    assert_eq!(row["expiresAtUnixSeconds"], expires_at);
    assert_eq!(
        row["receiptSha256"],
        hex::encode(Sha256::digest(std::fs::read(&receipt).unwrap()))
    );
    assert_eq!(
        encoded["digests"]["candidateSha256"],
        value["releaseCandidateSha256"]
    );
}

#[test]
fn receipt_without_qualification_stays_unqualified() {
    let fixture = prepared();
    let tuple = produce_with_observer(&fixture.app, &fixture.target, &FixedObserver).unwrap();
    let encoded = serde_json::to_value(tuple).unwrap();
    assert!(encoded.get("nativeEnrollmentQualification").is_none());
}

#[test]
fn reused_receipt_from_another_commit_or_bundle_is_rejected() {
    let (qualified_at, expires_at) = (now() - 100, now() + 800);
    for (key, replacement) in [
        ("sourceCommit", serde_json::json!("3".repeat(40))),
        ("releaseCandidateSha256", serde_json::json!(candidate())),
        ("desktopSha256", serde_json::json!("4".repeat(64))),
        ("artifactSha256", serde_json::json!("5".repeat(64))),
        ("checkLogSha256", serde_json::json!("6".repeat(63))),
    ] {
        let fixture = prepared();
        let mut value = receipt_value(&fixture, qualified_at, expires_at);
        if key == "releaseCandidateSha256" {
            value[key] = serde_json::json!("7".repeat(64));
        } else {
            value[key] = replacement;
        }
        let receipt = write_receipt(&fixture, &value);
        assert!(
            qualified(&fixture, &receipt, qualified_at, expires_at).is_err(),
            "{key}"
        );
    }
}

#[test]
fn expired_failed_or_mismatched_receipts_are_rejected() {
    let (qualified_at, expires_at) = (now() - 100, now() + 800);
    for (label, patch) in [
        (
            "expired",
            serde_json::json!({"qualifiedAtUnixSeconds": now() - 200, "expiresAtUnixSeconds": now() - 100}),
        ),
        (
            "failed check",
            serde_json::json!({"checkExitStatuses": [0, 1, 0]}),
        ),
        (
            "other checks",
            serde_json::json!({"checks": ["updater-metadata-tests", "codesign-bundle-strict", "other"]}),
        ),
        (
            "future qualification",
            serde_json::json!({"qualifiedAtUnixSeconds": now() + 100, "expiresAtUnixSeconds": now() + 900}),
        ),
        ("extra field", serde_json::json!({"releaseQualified": true})),
        (
            "uppercase commit",
            serde_json::json!({"sourceCommit": "A".repeat(40)}),
        ),
    ] {
        let fixture = prepared();
        let mut value = receipt_value(&fixture, qualified_at, expires_at);
        for (key, replacement) in patch.as_object().unwrap() {
            value[key] = replacement.clone();
        }
        let receipt = write_receipt(&fixture, &value);
        assert!(
            qualified(&fixture, &receipt, qualified_at, expires_at).is_err(),
            "{label}"
        );
    }
}

#[test]
fn qualification_bounds_must_match_the_receipt_and_target() {
    let fixture = prepared();
    let (qualified_at, expires_at) = (now() - 100, now() + 800);
    let value = receipt_value(&fixture, qualified_at, expires_at);
    let receipt = write_receipt(&fixture, &value);
    assert!(qualified(&fixture, &receipt, qualified_at, expires_at + 1).is_err());
    let mut short_target = fixture.target.clone();
    short_target.expires_at_unix_seconds = expires_at - 1;
    assert!(
        produce_qualified_with_observer(
            &fixture.app,
            &short_target,
            &receipt,
            qualified_at,
            expires_at,
            &FixedObserver,
        )
        .is_err()
    );
}
