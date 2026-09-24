use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::updater_installed_metadata::InstalledUpdateMetadataJournal;
use crate::{StagedUpdate, UpdateInstallState, UpdateJournal, UpdateTrustJournal, UpdateTrustRootV2};

use super::fixture_signing::{
    digest, fixture_signing_material, fixture_target, fixture_verified_update,
};
use super::super::{
    DaemonEnrollmentPolicy, DaemonIdentityVerifier, DaemonVerificationInput,
    NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission,
    VerifiedDaemonNativeEnrollmentPrepare, verify_with, verified_admission,
};

pub(super) struct Fixture {
    pub(super) _directory: tempfile::TempDir,
    pub(super) profile: PathBuf,
    pub(super) paths: NativeEnrollmentArtifactPathsV1,
    pub(super) trust: UpdateTrustRootV2,
    pub(super) policy: DaemonEnrollmentPolicy<'static>,
    pub(super) release: [u8; 32],
    pub(super) qualification: [u8; 32],
    pub(super) artifact: String,
    pub(super) journal: UpdateJournal,
    pub(super) trust_journal: UpdateTrustJournal,
    pub(super) metadata_path: PathBuf,
    pub(super) daemon: PathBuf,
    pub(super) contract: PathBuf,
}

struct FixtureArtifacts {
    directory: tempfile::TempDir,
    profile: PathBuf,
    paths: NativeEnrollmentArtifactPathsV1,
    hashes: [String; 4],
    daemon: PathBuf,
    contract: PathBuf,
}

pub(super) struct FixtureIdentity;

pub(super) struct RejectingIdentity;

impl DaemonIdentityVerifier for FixtureIdentity {
    fn confirm(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
        admission: &NativeEnrollmentTupleAdmission,
    ) -> bool {
        paths
            .confirm_current_daemon(admission.daemon_sha256)
            .is_ok()
    }
}

impl DaemonIdentityVerifier for RejectingIdentity {
    fn confirm(
        &self,
        _paths: &NativeEnrollmentArtifactPathsV1,
        _admission: &NativeEnrollmentTupleAdmission,
    ) -> bool {
        false
    }
}

fn fixture_artifacts() -> FixtureArtifacts {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile");
    let macos = directory.path().join("Runne.app/Contents/MacOS");
    let contract = directory
        .path()
        .join("Runne.app/Contents/Resources/contracts/gocode-ui-client-3/bundle.json");
    std::fs::create_dir_all(contract.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&macos).unwrap();
    let desktop = macos.join("runne-desktop");
    let writer = macos.join("runne");
    let daemon = macos.join("runned");
    for (path, bytes) in [
        (&desktop, b"desktop".as_slice()),
        (&writer, b"writer"),
        (&daemon, b"daemon"),
        (&contract, b"contract"),
    ] {
        std::fs::write(path, bytes).unwrap();
    }
    let hashes = [
        digest(b"desktop"),
        digest(b"writer"),
        digest(b"daemon"),
        digest(b"contract"),
    ];
    let paths =
        NativeEnrollmentArtifactPathsV1::new(&desktop, &writer, &daemon, &contract).unwrap();
    FixtureArtifacts {
        directory,
        profile,
        paths,
        hashes,
        daemon,
        contract,
    }
}

pub(super) fn fixture(expires_at: u64) -> Fixture {
    let artifacts = fixture_artifacts();
    let signing = fixture_signing_material();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (target, qualification) = fixture_target(expires_at, now, &artifacts.hashes);
    let (verified, release) =
        fixture_verified_update(target, expires_at, now, &artifacts.hashes, &signing);
    let updates = artifacts.profile.join("updates");
    let metadata_journal =
        InstalledUpdateMetadataJournal::new(updates.join("installed-metadata.json"));
    let metadata_binding = metadata_journal.persist(&verified).unwrap();
    let journal = UpdateJournal::new(updates.join("install-state.json"));
    let artifact = digest(b"installer");
    commit_record(&journal, &updates, &artifact, &metadata_binding);
    let trust_journal = UpdateTrustJournal::new(updates.join("trust-state.json"));
    trust_journal.initialize("1.0.0", "1.0.0").unwrap();
    trust_journal.accept_metadata(7, 9, "1.2.0").unwrap();
    trust_journal.commit_install("1.2.0").unwrap();
    Fixture {
        _directory: artifacts.directory,
        profile: artifacts.profile,
        paths: artifacts.paths,
        trust: signing.trust,
        policy: DaemonEnrollmentPolicy {
            profile_id: "profile",
            runtime_version: "0.1.0",
            channel: "stable",
        },
        release,
        qualification,
        artifact,
        journal,
        trust_journal,
        metadata_path: updates.join("installed-metadata.json.1.json"),
        daemon: artifacts.daemon,
        contract: artifacts.contract,
    }
}

pub(super) fn commit_record(
    journal: &UpdateJournal,
    updates: &Path,
    artifact: &str,
    metadata_binding: &str,
) {
    journal
        .record_staged_bound(
            "1.2.0",
            &StagedUpdate {
                path: updates.join("staged.dmg"),
                artifact_sha256: artifact.into(),
            },
            metadata_binding.into(),
        )
        .unwrap();
    for state in [
        UpdateInstallState::RestartRequired,
        UpdateInstallState::HealthCheck,
        UpdateInstallState::Committed,
    ] {
        journal.transition(state).unwrap();
    }
}

pub(super) fn verify(fixture: &Fixture) -> Option<VerifiedDaemonNativeEnrollmentPrepare> {
    verify_with(
        &input(fixture, fixture.release, fixture.qualification),
        &FixtureIdentity,
        || {},
    )
}

pub(in crate::updater_metadata) struct SignedFixtureAdmission {
    pub(in crate::updater_metadata) admission: NativeEnrollmentTupleAdmission,
    pub(in crate::updater_metadata) release: [u8; 32],
    pub(in crate::updater_metadata) qualification: [u8; 32],
    pub(in crate::updater_metadata) expires_at: u64,
}

pub(in crate::updater_metadata) fn signed_fixture_admission() -> SignedFixtureAdmission {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let fixture = fixture(now + 60);
    SignedFixtureAdmission {
        admission: verified_admission(
            &fixture.profile,
            &fixture.paths,
            &fixture.trust,
            &fixture.policy,
        )
        .unwrap(),
        release: fixture.release,
        qualification: fixture.qualification,
        expires_at: now + 60,
    }
}

pub(super) fn input(
    fixture: &Fixture,
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
) -> DaemonVerificationInput<'_> {
    DaemonVerificationInput {
        profile_directory: &fixture.profile,
        paths: &fixture.paths,
        trust: &fixture.trust,
        policy: &fixture.policy,
        release_tuple_digest,
        qualification_binding_digest,
    }
}
