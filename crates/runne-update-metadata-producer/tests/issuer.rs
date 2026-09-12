use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use runne_platform_desktop::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleV3, NativeEnrollmentTupleV3CodeIdentities,
    NativeEnrollmentTupleV3Deployment, NativeEnrollmentTupleV3Digests,
    NativeEnrollmentTupleV3ProtocolCompatibility, NativeEnrollmentTupleV3ProtocolVersions,
    UpdateTargetV2,
};
use runne_update_metadata_producer::{
    KeySlot, ProducerError, UpdateMetadataDraft, UpdateSigningKeyStore, issue_metadata,
};
use sha2::{Digest, Sha256};

struct MemoryKeys;

impl MemoryKeys {
    fn key(slot: KeySlot) -> SigningKey {
        let byte = match slot {
            KeySlot::RootA => 1,
            KeySlot::RootB => 2,
            KeySlot::RootC => 3,
            KeySlot::Snapshot => 4,
            KeySlot::Timestamp => 5,
        };
        SigningKey::from_bytes(&[byte; 32])
    }
}

impl UpdateSigningKeyStore for MemoryKeys {
    fn public_key(&self, slot: KeySlot) -> Result<[u8; 32], ProducerError> {
        Ok(Self::key(slot).verifying_key().to_bytes())
    }

    fn sign(&self, slot: KeySlot, bytes: &[u8]) -> Result<[u8; 64], ProducerError> {
        Ok(Self::key(slot).sign(bytes).to_bytes())
    }
}

fn draft(artifact_path: PathBuf) -> UpdateMetadataDraft {
    UpdateMetadataDraft {
        schema_version: 1,
        artifact_path,
        artifact_url: "https://updates.example.test/Runne.dmg".into(),
        product_id: "com.runne.desktop".into(),
        version: "0.0.2".into(),
        current_version: "0.0.1".into(),
        platform: "macos".into(),
        arch: "arm64".into(),
        release_candidate_sha256: "a".repeat(64),
        min_os: "macos-13".into(),
        profile_id: "gocode-ui-client/2".into(),
        bundle_sha256: "b".repeat(64),
        runtime_version: "0.1.0".into(),
        runtime_digest: "c".repeat(64),
        channel: "stable".into(),
        published_at_unix_seconds: 100,
        expires_at_unix_seconds: 500,
        rollback_floor: "0.0.1".into(),
        root_version: 1,
        targets_version: 1,
        snapshot_version: 1,
        timestamp_version: 1,
        native_enrollment_tuple_path: None,
    }
}

/// Rebuilds the target the issuer will derive from this draft, with the
/// artifact digest the issuer measures for `b"signed product"`.
fn harness_target(value: &UpdateMetadataDraft, artifact_sha256: String) -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: value.product_id.clone(),
        version: value.version.clone(),
        platform: value.platform.clone(),
        arch: value.arch.clone(),
        artifact_sha256,
        artifact_size: b"signed product".len() as u64,
        artifact_url: value.artifact_url.clone(),
        release_candidate_sha256: value.release_candidate_sha256.clone(),
        min_os: value.min_os.clone(),
        profile_id: value.profile_id.clone(),
        bundle_sha256: value.bundle_sha256.clone(),
        runtime_version: value.runtime_version.clone(),
        runtime_digest: value.runtime_digest.clone(),
        channel: value.channel.clone(),
        published_at_unix_seconds: value.published_at_unix_seconds,
        expires_at_unix_seconds: value.expires_at_unix_seconds,
        rollback_floor: value.rollback_floor.clone(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
        qualification_bootstrap_client_v1: None,
    }
}

fn dev_tuple(target: &UpdateTargetV2) -> NativeEnrollmentTupleV3 {
    let digest = |value: u64| format!("{value:064x}");
    let identity = |identifier: &str, value: u64| {
        MacOsCodeIdentityExpectationV1::new(identifier, "758F9Z45SR", format!("{value:040x}"))
            .unwrap()
    };
    NativeEnrollmentTupleV3::new(
        NativeEnrollmentTupleV3Digests {
            candidate_sha256: target.release_candidate_sha256.clone(),
            desktop_sha256: digest(1),
            writer_sha256: digest(2),
            daemon_sha256: digest(3),
            credential_service_sha256: digest(4),
            launch_agent_plist_sha256: digest(5),
            entitlements_sha256: digest(6),
            provisioning_sha256: digest(7),
            xpc_protocol_sha256: digest(8),
            contract_sha256: target.bundle_sha256.clone(),
        },
        NativeEnrollmentTupleV3Deployment::exact(NativeEnrollmentTupleV3ProtocolVersions::new(
            vec![NativeEnrollmentTupleV3ProtocolCompatibility::new(
                1, 1, 1, 1, 1, 1, 1,
            )],
        )),
        NativeEnrollmentTupleV3CodeIdentities::new(
            identity("com.runne.desktop", 1),
            identity("runne", 2),
            identity("runned", 3),
            identity("com.runne.credential-service", 4),
        ),
        target,
    )
    .unwrap()
}

/// Serializes the same `{"schemaVersion":1,"target":...,"tuple":...}` wrapper
/// the `dev_enrollment_tuple` harness writes.
fn write_tuple_file(
    directory: &Path,
    target: &UpdateTargetV2,
    tuple: &NativeEnrollmentTupleV3,
) -> PathBuf {
    let path = directory.join("tuple.json");
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schemaVersion": 1,
        "target": target,
        "tuple": tuple,
    }))
    .unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

fn write_artifact(directory: &Path) -> (PathBuf, String) {
    let artifact = directory.join("Runne.dmg");
    std::fs::write(&artifact, b"signed product").unwrap();
    let artifact_sha256 = hex::encode(Sha256::digest(b"signed product"));
    (artifact, artifact_sha256)
}

#[test]
fn producer_hashes_artifact_signs_threshold_roles_and_self_verifies() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("Runne.dmg");
    std::fs::write(&artifact, b"signed product").unwrap();
    let metadata = issue_metadata(&draft(artifact), &MemoryKeys).unwrap();
    assert_eq!(metadata.schema_version, 2);
    assert_eq!(metadata.root_signatures.len(), 2);
    assert_eq!(metadata.targets_signatures.len(), 2);
    assert_eq!(metadata.targets.target.artifact_size, 14);
    assert_eq!(metadata.targets.target.version, "0.0.2");
    assert_ne!(metadata.snapshot_signature, metadata.timestamp_signature);
}

#[test]
fn producer_embeds_native_enrollment_tuple_v3_from_draft_path() {
    let directory = tempfile::tempdir().unwrap();
    let (artifact, artifact_sha256) = write_artifact(directory.path());
    let target = harness_target(&draft(artifact.clone()), artifact_sha256);
    let tuple = dev_tuple(&target);
    let mut value = draft(artifact);
    value.native_enrollment_tuple_path = Some(write_tuple_file(directory.path(), &target, &tuple));
    let metadata = issue_metadata(&value, &MemoryKeys).unwrap();
    assert_eq!(
        metadata.targets.target.native_enrollment_tuple_v3.as_ref(),
        Some(&tuple)
    );
}

#[test]
fn producer_keeps_native_enrollment_tuple_v3_absent_without_draft_path() {
    let directory = tempfile::tempdir().unwrap();
    let (artifact, _) = write_artifact(directory.path());
    let metadata = issue_metadata(&draft(artifact), &MemoryKeys).unwrap();
    assert!(metadata.targets.target.native_enrollment_tuple_v3.is_none());
}

#[test]
fn producer_rejects_tuple_bound_to_a_different_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let (artifact, _) = write_artifact(directory.path());
    // Bind the tuple to a different artifact digest than the draft measures.
    let mismatched = harness_target(&draft(artifact.clone()), "d".repeat(64));
    let tuple = dev_tuple(&mismatched);
    let mut value = draft(artifact);
    value.native_enrollment_tuple_path =
        Some(write_tuple_file(directory.path(), &mismatched, &tuple));
    assert_eq!(
        issue_metadata(&value, &MemoryKeys),
        Err(ProducerError::Verification)
    );
}

#[test]
fn producer_rejects_non_absolute_artifact_path() {
    let result = issue_metadata(&draft(PathBuf::from("Runne.dmg")), &MemoryKeys);
    assert_eq!(result, Err(ProducerError::Input));
}

#[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
#[test]
fn dev_producer_self_verifies_exact_loopback_artifact_url() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("Runne.dmg");
    std::fs::write(&artifact, b"signed product").unwrap();
    let mut value = draft(artifact);
    value.artifact_url = "http://127.0.0.1:8080/Runne.dmg".into();
    assert!(issue_metadata(&value, &MemoryKeys).is_ok());
    value.artifact_url = "http://localhost:8080/Runne.dmg".into();
    assert_eq!(
        issue_metadata(&value, &MemoryKeys),
        Err(ProducerError::Verification)
    );
}
