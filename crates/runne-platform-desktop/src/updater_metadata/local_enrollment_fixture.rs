use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use super::{
    NativeEnrollmentArtifactPathsV1, NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleV2,
    PreparedInstalledNativeEnrollment, UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2,
    UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetV2Binding, UpdateTargetsRoleV2,
    UpdateTimestampRoleV2, UpdateTrustRootV2, verify_update_v2,
};
use crate::updater_installed_metadata::InstalledUpdateMetadataJournal;
use crate::{
    StagedUpdate, UpdateCoordinator, UpdateInstallState, UpdateJournal, UpdateTargetBindingConfig,
    UpdateTrustJournal,
};

const VERSION: &str = "1.2.0";
const FLOOR: &str = "1.0.0";

/// Installs short-lived signed metadata for the exact current local package.
///
/// This fixture exists only in the `test-support` graph and returns an opaque,
/// move-only admission. It does not qualify or publish the local result.
#[doc(hidden)]
#[must_use]
pub fn prepare_local_native_enrollment(
    profile: &Path,
) -> Option<PreparedInstalledNativeEnrollment> {
    if !runne_api::test_support::local_native_enrollment_enabled() {
        return None;
    }
    let paths = NativeEnrollmentArtifactPathsV1::resolve_installed().ok()?;
    let artifacts = paths.measure().ok()?;
    let updates = profile.join("updates");
    let journal = UpdateJournal::new(updates.join("install-state.json"));
    if journal.read().ok()?.is_some() {
        return UpdateCoordinator::new(test_trust(), binding_config(&artifacts), profile)
            .ok()?
            .prepare_installed_native_enrollment()
            .ok()?;
    }
    let metadata = signed_metadata(&artifacts)?;
    let trust = test_trust();
    let now = unix_seconds()?;
    let binding = UpdateTargetV2Binding {
        product_id: "com.runne.desktop",
        platform: "macos",
        arch: "arm64",
        min_os: "macos-13",
        profile_id: "slice-e-local",
        bundle_sha256: &artifacts.contract_sha256,
        runtime_version: "0.1.0",
        runtime_digest: &artifacts.daemon_sha256,
        channel: "local",
    };
    let verified = verify_update_v2(&metadata, &trust, &binding, now, VERSION, FLOOR).ok()?;
    persist(profile, &verified)?;
    verified
        .admit_native_enrollment(&artifacts)?
        .with_local_code_identities(&paths)?
        .retain_installed_paths(paths)
        .into()
}

fn binding_config(
    artifacts: &super::MeasuredNativeEnrollmentArtifactsV1,
) -> UpdateTargetBindingConfig {
    UpdateTargetBindingConfig {
        product_id: "com.runne.desktop".into(),
        platform: "macos".into(),
        arch: "arm64".into(),
        min_os: "macos-13".into(),
        profile_id: "slice-e-local".into(),
        bundle_sha256: artifacts.contract_sha256.clone(),
        runtime_version: "0.1.0".into(),
        runtime_digest: artifacts.daemon_sha256.clone(),
        channel: "local".into(),
    }
}

fn signed_metadata(
    artifacts: &super::MeasuredNativeEnrollmentArtifactsV1,
) -> Option<UpdateMetadataV2> {
    let now = unix_seconds()?;
    let expires = now.checked_add(3_600)?;
    let roots = [11_u8, 12, 13].map(|byte| SigningKey::from_bytes(&[byte; 32]));
    let timestamp = SigningKey::from_bytes(&[14; 32]);
    let snapshot = SigningKey::from_bytes(&[15; 32]);
    let trust = test_trust();
    let mut target = UpdateTargetV2 {
        product_id: "com.runne.desktop".into(),
        version: VERSION.into(),
        platform: "macos".into(),
        arch: "arm64".into(),
        artifact_sha256: digest(b"slice-e-local-package"),
        artifact_size: 1,
        artifact_url: "https://local.invalid/runne.dmg".into(),
        release_candidate_sha256: digest(b"slice-e-local-candidate"),
        min_os: "macos-13".into(),
        profile_id: "slice-e-local".into(),
        bundle_sha256: artifacts.contract_sha256.clone(),
        runtime_version: "0.1.0".into(),
        runtime_digest: artifacts.daemon_sha256.clone(),
        channel: "local".into(),
        published_at_unix_seconds: now.saturating_sub(1),
        expires_at_unix_seconds: expires,
        rollback_floor: FLOOR.into(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
    };
    let tuple = NativeEnrollmentTupleV2::new_macos(
        target.release_candidate_sha256.clone(),
        artifacts.desktop_sha256.clone(),
        artifacts.writer_sha256.clone(),
        artifacts.daemon_sha256.clone(),
        artifacts.contract_sha256.clone(),
        "dev.runne.desktop",
        "LOCAL00001",
        "1".repeat(40),
        "dev.runne.writer",
        "LOCAL00002",
        "2".repeat(40),
        "dev.runne.daemon",
        "LOCAL00003",
        "3".repeat(40),
        &target,
    )
    .ok()?;
    let row = NativeEnrollmentQualificationRowV1::new(
        &target,
        &tuple,
        digest(b"slice-e-local-unqualified"),
        now,
        expires,
    )
    .ok()?;
    target.native_enrollment_tuple = Some(tuple.with_qualification(&target, row).ok()?);
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 {
        version: 8,
        expires_at_unix_seconds: expires,
        target,
    };
    let snapshot_role = UpdateSnapshotRoleV2 {
        version: 9,
        expires_at_unix_seconds: expires,
        targets_version: 8,
    };
    let timestamp_role = UpdateTimestampRoleV2 {
        version: 10,
        expires_at_unix_seconds: expires,
        snapshot_version: 9,
    };
    Some(UpdateMetadataV2 {
        schema_version: 2,
        root: root.clone(),
        targets: targets.clone(),
        snapshot: snapshot_role.clone(),
        timestamp: timestamp_role.clone(),
        root_signatures: signatures(&roots, &root),
        targets_signatures: signatures(&roots, &targets),
        snapshot_signature: signed(&snapshot, &snapshot_role),
        timestamp_signature: signed(&timestamp, &timestamp_role),
    })
}

fn persist(profile: &Path, verified: &super::VerifiedUpdateV2) -> Option<()> {
    let updates = profile.join("updates");
    let metadata = InstalledUpdateMetadataJournal::new(updates.join("installed-metadata.json"));
    let binding = metadata.persist(verified).ok()?;
    let journal = UpdateJournal::new(updates.join("install-state.json"));
    journal
        .record_staged_bound(
            VERSION,
            &StagedUpdate {
                path: updates.join("local.dmg"),
                artifact_sha256: verified.target().artifact_sha256.clone(),
            },
            binding,
        )
        .ok()?;
    for state in [
        UpdateInstallState::RestartRequired,
        UpdateInstallState::HealthCheck,
        UpdateInstallState::Committed,
    ] {
        journal.transition(state).ok()?;
    }
    let trust = UpdateTrustJournal::new(updates.join("trust-state.json"));
    trust.initialize(FLOOR, FLOOR).ok()?;
    trust.accept_metadata(7, 9, VERSION).ok()?;
    trust.commit_install(VERSION).ok()?;
    Some(())
}

fn test_trust() -> UpdateTrustRootV2 {
    let keys = [11_u8, 12, 13, 14, 15].map(|byte| {
        SigningKey::from_bytes(&[byte; 32])
            .verifying_key()
            .to_bytes()
    });
    UpdateTrustRootV2::from_keys(
        [
            ("root-a", keys[0]),
            ("root-b", keys[1]),
            ("root-c", keys[2]),
        ],
        ("timestamp", keys[3]),
        ("snapshot", keys[4]),
    )
}

fn signatures<T: serde::Serialize>(keys: &[SigningKey; 3], value: &T) -> Vec<UpdateSignatureV2> {
    ["root-a", "root-b"]
        .into_iter()
        .zip(keys)
        .map(|(key_id, key)| UpdateSignatureV2 {
            key_id: key_id.into(),
            signature: signed(key, value),
        })
        .collect()
}

fn signed<T: serde::Serialize>(key: &SigningKey, value: &T) -> String {
    hex::encode(
        key.sign(&serde_json::to_vec(value).expect("local fixture role"))
            .to_bytes(),
    )
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|v| v.as_secs())
}
