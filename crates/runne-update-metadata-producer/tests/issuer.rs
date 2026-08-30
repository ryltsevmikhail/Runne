use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use runne_update_metadata_producer::{
    KeySlot, ProducerError, UpdateMetadataDraft, UpdateSigningKeyStore, issue_metadata,
};

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
    }
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
fn producer_rejects_non_absolute_artifact_path() {
    let result = issue_metadata(&draft(PathBuf::from("Runne.dmg")), &MemoryKeys);
    assert_eq!(result, Err(ProducerError::Input));
}
