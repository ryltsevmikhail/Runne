use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn target() -> super::UpdateTarget {
    super::UpdateTarget {
        product_id: "com.runne.desktop".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
    }
}

fn signed_update(key: &SigningKey, bytes: &[u8]) -> super::UpdateMetadataV1 {
    let payload = super::UpdatePayloadV1 {
        schema_version: 1,
        product_id: "com.runne.desktop".into(),
        version: "1.2.3".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        artifact_sha256: hex::encode(Sha256::digest(bytes)),
        artifact_size: bytes.len() as u64,
        expires_at_unix_seconds: 500,
    };
    let signature = key.sign(&serde_json::to_vec(&payload).unwrap());
    super::UpdateMetadataV1 {
        payload,
        signature: hex::encode(signature.to_bytes()),
    }
}

#[test]
fn verifies_signed_target_and_stages_without_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let bytes = b"signed artifact";
    let key = SigningKey::from_bytes(&[7; 32]);
    let metadata = signed_update(&key, bytes);
    let verified = super::verify_update(
        &metadata,
        &key.verifying_key().to_bytes(),
        &target(),
        100,
        "1.0.0",
        "1.0.0",
    )
    .unwrap();
    let destination = directory.path().join("runne-update.bin");
    let staged = super::stage_verified_artifact(&destination, &verified, bytes).unwrap();
    assert_eq!(staged.path, destination);
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    assert_eq!(
        super::stage_verified_artifact(&destination, &verified, bytes),
        Err(super::UpdateVerificationError::StageFailed)
    );
}

#[test]
fn rejects_expired_wrong_target_and_rollback_metadata() {
    let bytes = b"artifact";
    let key = SigningKey::from_bytes(&[8; 32]);
    let metadata = signed_update(&key, bytes);
    assert_eq!(
        super::verify_update(
            &metadata,
            &key.verifying_key().to_bytes(),
            &target(),
            500,
            "1.0.0",
            "1.0.0"
        ),
        Err(super::UpdateVerificationError::Expired)
    );
    let metadata = signed_update(&key, bytes);
    assert_eq!(
        super::verify_update(
            &metadata,
            &key.verifying_key().to_bytes(),
            &target(),
            100,
            "2.0.0",
            "1.0.0"
        ),
        Err(super::UpdateVerificationError::Rollback)
    );
    let mut metadata = signed_update(&key, bytes);
    metadata.payload.version = "0.9.0".into();
    assert_eq!(
        super::verify_update(
            &metadata,
            &key.verifying_key().to_bytes(),
            &target(),
            100,
            "1.0.0",
            "1.0.0"
        ),
        Err(super::UpdateVerificationError::InvalidSignature)
    );
}

#[test]
fn install_transaction_requires_quiescence_confirmation_and_health() {
    let staged = super::StagedUpdate {
        path: std::path::PathBuf::from("runne-update.bin"),
        artifact_sha256: "1".repeat(64),
    };
    assert_eq!(
        super::UpdateInstallPlan::prepare(staged.clone(), 1, false),
        Err(super::UpdateInstallError::ActiveTaskRuns)
    );

    let plan = super::UpdateInstallPlan::prepare(staged, 1, true).unwrap();
    assert_eq!(plan.state(), super::UpdateInstallState::Staged);
    let plan = plan.begin_restart().unwrap();
    assert_eq!(plan.state(), super::UpdateInstallState::RestartRequired);
    let plan = plan.begin_health_check().unwrap();
    assert_eq!(plan.state(), super::UpdateInstallState::HealthCheck);
    let rolled_back = plan.complete_health(false).unwrap();
    assert_eq!(rolled_back.state(), super::UpdateInstallState::RolledBack);
}

#[test]
fn install_transaction_rejects_skipped_lifecycle_transitions() {
    let staged = super::StagedUpdate {
        path: std::path::PathBuf::from("runne-update.bin"),
        artifact_sha256: "2".repeat(64),
    };
    let plan = super::UpdateInstallPlan::prepare(staged, 0, false).unwrap();
    assert_eq!(
        plan.begin_health_check(),
        Err(super::UpdateInstallError::InvalidTransition)
    );
}

#[test]
fn update_journal_round_trips_staged_transaction_and_transitions() {
    let directory = tempfile::tempdir().unwrap();
    let journal = super::UpdateJournal::new(directory.path().join("install-state.json"));
    let staged = super::StagedUpdate {
        path: directory.path().join("runne-update.bin"),
        artifact_sha256: "a".repeat(64),
    };
    journal.record_staged("1.2.3", &staged).unwrap();
    assert_eq!(
        journal.read().unwrap().unwrap().state,
        super::UpdateInstallState::Staged
    );
    journal
        .transition(super::UpdateInstallState::RestartRequired)
        .unwrap();
    journal
        .transition(super::UpdateInstallState::HealthCheck)
        .unwrap();
    journal
        .transition(super::UpdateInstallState::Committed)
        .unwrap();
    let record = journal.read().unwrap().unwrap();
    assert_eq!(record.version, "1.2.3");
    assert_eq!(record.state, super::UpdateInstallState::Committed);
    assert_eq!(record.staged_path, staged.path);
}

#[test]
fn update_journal_rejects_corruption_and_invalid_transition() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("install-state.json");
    let journal = super::UpdateJournal::new(path.clone());
    std::fs::write(&path, br#"{"schemaVersion":1,"state":"staged","version":"1.2.3","artifactSha256":"bad","stagedPath":"/tmp/x"}"#).unwrap();
    assert_eq!(journal.read(), Err(super::UpdateJournalError::Corrupt));
    journal.clear().unwrap();
    assert_eq!(journal.read().unwrap(), None);
    assert_eq!(
        journal.transition(super::UpdateInstallState::HealthCheck),
        Err(super::UpdateJournalError::NoTransaction)
    );
}

fn signed_role<T: serde::Serialize>(key: &SigningKey, role: &T) -> String {
    hex::encode(key.sign(&serde_json::to_vec(role).unwrap()).to_bytes())
}

#[test]
#[allow(clippy::too_many_lines)]
fn v2_update_requires_two_root_and_two_targets_signatures() {
    let roots = [
        SigningKey::from_bytes(&[21; 32]),
        SigningKey::from_bytes(&[22; 32]),
        SigningKey::from_bytes(&[23; 32]),
    ];
    let timestamp = SigningKey::from_bytes(&[24; 32]);
    let snapshot = SigningKey::from_bytes(&[25; 32]);
    let trust = super::UpdateTrustRootV2::from_keys(
        [
            ("root-a", roots[0].verifying_key().to_bytes()),
            ("root-b", roots[1].verifying_key().to_bytes()),
            ("root-c", roots[2].verifying_key().to_bytes()),
        ],
        ("timestamp", timestamp.verifying_key().to_bytes()),
        ("snapshot", snapshot.verifying_key().to_bytes()),
    );
    let target = super::UpdateTargetV2 {
        product_id: "com.runne.desktop".into(),
        version: "1.2.3".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        artifact_sha256: "a".repeat(64),
        artifact_size: 10,
        artifact_url: "https://updates.example.test/runne.AppImage".into(),
        min_os: "ubuntu-22.04".into(),
        profile_id: "gocode-ui-client/2".into(),
        bundle_sha256: "b".repeat(64),
        runtime_version: "0.1.0".into(),
        runtime_digest: "c".repeat(64),
        channel: "stable".into(),
        published_at_unix_seconds: 100,
        expires_at_unix_seconds: 500,
        rollback_floor: "1.0.0".into(),
    };
    let root = super::UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = super::UpdateTargetsRoleV2 {
        version: 8,
        expires_at_unix_seconds: 500,
        target: target.clone(),
    };
    let snapshot_role = super::UpdateSnapshotRoleV2 {
        version: 9,
        expires_at_unix_seconds: 500,
        targets_version: 8,
    };
    let timestamp_role = super::UpdateTimestampRoleV2 {
        version: 10,
        expires_at_unix_seconds: 500,
        snapshot_version: 9,
    };
    let metadata = super::UpdateMetadataV2 {
        schema_version: 2,
        root: root.clone(),
        targets: targets.clone(),
        snapshot: snapshot_role.clone(),
        timestamp: timestamp_role.clone(),
        root_signatures: vec![
            super::UpdateSignatureV2 {
                key_id: "root-a".into(),
                signature: signed_role(&roots[0], &root),
            },
            super::UpdateSignatureV2 {
                key_id: "root-b".into(),
                signature: signed_role(&roots[1], &root),
            },
        ],
        targets_signatures: vec![
            super::UpdateSignatureV2 {
                key_id: "root-a".into(),
                signature: signed_role(&roots[0], &targets),
            },
            super::UpdateSignatureV2 {
                key_id: "root-b".into(),
                signature: signed_role(&roots[1], &targets),
            },
        ],
        snapshot_signature: signed_role(&snapshot, &snapshot_role),
        timestamp_signature: signed_role(&timestamp, &timestamp_role),
    };
    let binding = super::UpdateTargetV2Binding {
        product_id: "com.runne.desktop",
        platform: "linux",
        arch: "x86_64",
        min_os: "ubuntu-22.04",
        profile_id: "gocode-ui-client/2",
        bundle_sha256: &target.bundle_sha256,
        runtime_version: "0.1.0",
        runtime_digest: &target.runtime_digest,
        channel: "stable",
    };
    let verified =
        super::verify_update_v2(&metadata, &trust, &binding, 100, "1.0.0", "1.0.0").unwrap();
    assert_eq!(verified.target().version, "1.2.3");
    assert_eq!(
        super::verify_update_v2(&metadata, &trust, &binding, 600, "1.0.0", "1.0.0"),
        Err(super::UpdateV2VerificationError::Expired)
    );
    assert_eq!(
        super::verify_update_v2(&metadata, &trust, &binding, 100, "2.0.0", "1.0.0"),
        Err(super::UpdateV2VerificationError::Rollback)
    );
    let mut mixed = metadata.clone();
    mixed.snapshot.targets_version = 99;
    assert_eq!(
        super::verify_update_v2(&mixed, &trust, &binding, 100, "1.0.0", "1.0.0"),
        Err(super::UpdateV2VerificationError::InvalidMetadata)
    );
    let mut insufficient = metadata;
    insufficient.targets_signatures.pop();
    assert_eq!(
        super::verify_update_v2(&insufficient, &trust, &binding, 100, "1.0.0", "1.0.0"),
        Err(super::UpdateV2VerificationError::TargetsQuorum)
    );
}
