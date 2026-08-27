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

mod updater_enrollment_tuple;
mod updater_v2;
