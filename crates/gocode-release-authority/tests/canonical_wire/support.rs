use gocode_release_authority::CanonicalPayloadKind;
use serde_json::{Value, json};
use std::collections::BTreeMap;
mod release_facts_support;
pub mod threshold_fixture;

const D: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const E: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub fn payload(kind: CanonicalPayloadKind) -> Vec<u8> {
    let value = match kind {
        CanonicalPayloadKind::Rc1Decision => rc1(),
        CanonicalPayloadKind::UnsignedManifest => manifest(),
        CanonicalPayloadKind::Rc2Authorization => rc2_authorization(),
        CanonicalPayloadKind::ArtifactRecord => artifact_value("linux"),
        CanonicalPayloadKind::ThresholdMetadata => metadata(),
        CanonicalPayloadKind::Inventory => inventory(),
        CanonicalPayloadKind::VerificationReport => report(),
        CanonicalPayloadKind::PublicationManifest => publication(),
        CanonicalPayloadKind::Rc3Authorization => rc3_authorization(),
        CanonicalPayloadKind::Snapshot => snapshot(),
    };
    let mut raw = serde_json::to_vec(&value).unwrap();
    raw.push(b'\n');
    raw
}

fn map(items: Vec<(&str, Value)>) -> Value {
    json!(items.into_iter().collect::<BTreeMap<_, _>>())
}

fn rc1() -> Value {
    map(vec![
        (
            "schema_version",
            json!("gocode.release.rc1-qualification-decision/1"),
        ),
        (
            "candidate_binding_sha256",
            json!("6a67c5ffe4b247f14960579171318a74af22d51eb66232f4aef512267d37911c"),
        ),
        ("subject_sha256", json!(D)),
        ("matrix_sha256", json!(D)),
        ("bootstrap_sha256", json!(D)),
        ("candidate_sha256", json!(D)),
        ("policy_sha256", json!(D)),
        ("release_facts_sha256", json!(D)),
        (
            "approver",
            json!({"principal_id":"principal","account_id":"account","lane_id":"lane","key_id":"key","signature_profile_id":"profile"}),
        ),
        ("valid_from", json!(1)),
        ("expires_at", json!(2)),
        ("revocation_epoch", json!(1)),
        ("disposition", json!("qualified_unsigned")),
        ("signing_allowed", json!(false)),
        ("publication_allowed", json!(false)),
        ("external_effects", json!([])),
    ])
}

fn manifest() -> Value {
    release_facts_support::manifest(D)
}

fn rc2_authorization() -> Value {
    map(vec![
        (
            "schema_version",
            json!("gocode.release.rc2-signing-authorization/1"),
        ),
        ("parent_candidate_sha256", json!(D)),
        ("unsigned_manifest_sha256", json!(D)),
        (
            "pre_sign_artifacts",
            json!([
                {"artifact_slot_id":"linux-appimage","platform":"linux","operation":"native_sign","expected_artifact_sha256":D,"expected_artifact_length":1},
                {"artifact_slot_id":"linux-deb","platform":"linux","operation":"native_sign","expected_artifact_sha256":D,"expected_artifact_length":2},
                {"artifact_slot_id":"windows-installer-unsigned","platform":"windows","operation":"native_sign","expected_artifact_sha256":D,"expected_artifact_length":5}
            ]),
        ),
        ("signer", identity("signer")),
        ("runner", identity("runner")),
        ("reviewer", identity("reviewer")),
        ("update_issuer", identity("issuer")),
        ("workflow_sha256", json!(D)),
        ("effect_namespace", json!("namespace")),
        ("effect_generation", json!(1)),
        ("valid_from", json!(1)),
        ("expires_at", json!(2)),
        ("revocation_epoch", json!(1)),
    ])
}

fn identity(name: &str) -> Value {
    json!({
        "principal_id":format!("{name}-principal"),"account_id":format!("{name}-account"),
        "lane_id":format!("{name}-lane"),"key_id":format!("{name}-key"),
        "signature_profile_id":format!("{name}-profile")
    })
}

#[allow(dead_code)]
pub fn artifact(platform: &str) -> Vec<u8> {
    let mut raw = serde_json::to_vec(&artifact_value(platform)).unwrap();
    raw.push(b'\n');
    raw
}

fn artifact_value(platform: &str) -> Value {
    let slot = match platform {
        "linux" => "linux-appimage",
        "windows" => "windows-installer-unsigned",
        "macos_preview" => "macos-app-development-adhoc",
        _ => "invalid-slot",
    };
    map(vec![
        (
            "schema_version",
            json!("gocode.release.rc2-signed-artifact-record/2"),
        ),
        ("artifact_slot_id", json!(slot)),
        ("platform", json!(platform)),
        ("artifact_sha256", json!(D)),
        ("parent_candidate_sha256", json!(D)),
        ("signing_authorization_sha256", json!(D)),
        ("workflow_sha256", json!(D)),
        ("effect_namespace", json!("namespace")),
        ("effect_generation", json!(1)),
        ("operation", json!("native_sign")),
        ("pre_sign_artifact_sha256", json!(D)),
        ("pre_sign_artifact_length", json!(1)),
        ("artifact_length", json!(u64::MAX)),
        ("native_signature_attestation_sha256", json!(D)),
        (
            "certificate_chain_attestation_sha256",
            json!("b".repeat(64)),
        ),
        ("timestamp_attestation_sha256", json!("c".repeat(64))),
        ("secret_scan_attestation_sha256", json!("d".repeat(64))),
        ("advisory_scan_attestation_sha256", json!("e".repeat(64))),
        (
            "package_inspection_attestation_sha256",
            json!("f".repeat(64)),
        ),
        ("install_attestation_sha256", json!("1".repeat(64))),
        ("upgrade_attestation_sha256", json!("2".repeat(64))),
        ("rollback_attestation_sha256", json!("3".repeat(64))),
        ("uninstall_attestation_sha256", json!("4".repeat(64))),
        ("signer", identity("signer")),
        ("runner", identity("runner")),
        ("public_disposition", json!("public")),
    ])
}

fn metadata() -> Value {
    threshold_fixture::metadata(D)
}

fn inventory() -> Value {
    map(vec![
        (
            "schema_version",
            json!("gocode.release.signed-envelope-inventory/1"),
        ),
        ("parent_candidate_sha256", json!(D)),
        (
            "artifact_records",
            json!([
                D,
                E,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            ]),
        ),
        ("macos_preview_separate", json!(true)),
    ])
}

fn report() -> Value {
    map(vec![
        (
            "schema_version",
            json!("gocode.release.signed-envelope-verification-report/1"),
        ),
        ("inventory_sha256", json!(D)),
        ("metadata_set_sha256", json!(D)),
        ("linux_verified", json!(true)),
        ("windows_verified", json!(true)),
        ("disposition", json!("native_verified")),
        ("linux_native_outcome", json!("verified")),
        ("windows_native_outcome", json!("verified")),
    ])
}

fn publication() -> Value {
    map(vec![
        (
            "schema_version",
            json!("gocode.release.publication-manifest/1"),
        ),
        ("candidate_sha256", json!(D)),
        ("inventory_sha256", json!(D)),
        ("report_sha256", json!(D)),
        ("metadata_set_sha256", json!(D)),
        ("human_artifact_sha256", json!([D, D, D, D, D])),
        (
            "human_artifact_categories",
            json!([
                "release_notes",
                "changelog",
                "compatibility_support",
                "provenance",
                "sbom"
            ]),
        ),
        ("version", json!("1.0.0")),
        ("channel", json!("stable")),
        ("destination", json!("repo/releases")),
        ("artifacts", json!(["linux", "windows"])),
        ("rollback_policy_sha256", json!(D)),
        ("rollout_policy_sha256", json!(D)),
        ("macos_preview_excluded", json!(true)),
    ])
}

fn rc3_authorization() -> Value {
    map(vec![
        (
            "schema_version",
            json!("gocode.release.rc3-publication-authorization/1"),
        ),
        ("inventory_sha256", json!(D)),
        ("report_sha256", json!(D)),
        ("publication_manifest_sha256", json!(D)),
        ("executor_principal", json!("executor")),
        ("lane", json!("lane")),
        ("workflow_sha256", json!(D)),
        ("idempotency_namespace", json!("namespace")),
        ("destination", json!("repo/releases")),
        ("channel", json!("stable")),
        ("valid_from", json!(1)),
        ("expires_at", json!(2)),
        ("revocation_epoch", json!(1)),
        ("no_effect", json!(true)),
        ("external_effects", json!([])),
    ])
}

fn snapshot() -> Value {
    map(vec![
        (
            "schema_version",
            json!("gocode.release.promotion-state-snapshot/1"),
        ),
        ("promotion_id", json!("promotion")),
        ("revision", json!(u64::MAX)),
        ("state", json!("publication_authorized")),
        ("candidate_binding_sha256", json!(D)),
        ("candidate_sha256", json!(D)),
        ("effect_generation", json!(u64::MAX)),
        ("previous_snapshot_sha256", json!(D)),
        ("command_fingerprint_sha256", json!(D)),
        ("domain", json!("production")),
    ])
}
