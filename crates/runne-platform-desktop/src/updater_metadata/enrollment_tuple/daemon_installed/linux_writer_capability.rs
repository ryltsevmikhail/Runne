//! Linux installed-release writer capability minted from signed committed state.

use std::{
    os::unix::{
        fs::{MetadataExt as _, PermissionsExt as _},
        net::UnixStream,
    },
    path::{Path, PathBuf},
};

use super::super::{
    NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission,
    enrollment_paths::LinuxAuthenticatedDesktopPeer,
};
use super::compiled_policy;
#[path = "linux_writer_capability/linux_admission.rs"]
mod linux_admission;
use linux_admission::{refresh_linux_admission, verified_linux_admission};
#[path = "linux_writer_capability/staged_writer.rs"]
mod staged_writer;

#[inline]
#[cfg(feature = "linux-native-enrollment-qualification")]
fn linux_stage(stage: &'static str) {
    crate::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage(stage);
}

#[inline]
#[cfg(not(feature = "linux-native-enrollment-qualification"))]
const fn linux_stage(stage: &'static str) {
    let _ = stage;
}

/// Opaque daemon-owned Linux writer admission, bound to a live desktop peer.
/// The value grants a launch spec only while its signed installed tuple remains current.
pub struct VerifiedInstalledLinuxWriterCapability {
    peer: LinuxAuthenticatedDesktopPeer,
    paths: NativeEnrollmentArtifactPathsV1,
    admission: NativeEnrollmentTupleAdmission,
    profile_directory: PathBuf,
    runtime_root: PathBuf,
}

impl VerifiedInstalledLinuxWriterCapability {
    /// Loads committed signed metadata and resolves package files from the authenticated peer.
    /// `resource_directory_hint` locates the contract file; it does not provide trust evidence.
    #[must_use]
    pub fn load_current_for_authenticated_desktop_peer(
        profile_directory: &Path,
        canonical_runtime_root: &Path,
        resource_directory_hint: &Path,
        stream: &UnixStream,
    ) -> Option<Self> {
        linux_stage("capability_profile_runtime");
        if !valid_profile_runtime_pair(profile_directory, canonical_runtime_root) {
            return None;
        }
        linux_stage("capability_peer_paths");
        let (paths, peer) = NativeEnrollmentArtifactPathsV1::resolve_linux_from_authenticated_peer(
            stream,
            resource_directory_hint,
        )
        .ok()?;
        linux_stage("capability_policy");
        let policy = compiled_policy()?;
        linux_stage("capability_trust");
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        linux_stage("capability_admission");
        let admission = verified_linux_admission(
            profile_directory,
            canonical_runtime_root,
            &paths,
            &trust,
            &policy,
        )?;
        linux_stage("capability_identity");
        let identity = paths
            .confirm_current_daemon(admission.daemon_sha256, canonical_runtime_root)
            .is_ok();
        if !identity || paths.confirm_authenticated_peer(&peer, stream).is_err() {
            return None;
        }
        linux_stage("capability_refresh");
        let fresh = refresh_linux_admission(
            profile_directory,
            canonical_runtime_root,
            &paths,
            &trust,
            &policy,
            &admission,
            now()?,
        )?;
        if fresh != admission
            || paths
                .confirm_current_daemon(admission.daemon_sha256, canonical_runtime_root)
                .is_err()
            || paths.confirm_authenticated_peer(&peer, stream).is_err()
            || !valid_profile_runtime_pair(profile_directory, canonical_runtime_root)
        {
            return None;
        }
        Some(Self {
            peer,
            paths,
            admission: fresh,
            profile_directory: profile_directory.to_path_buf(),
            runtime_root: canonical_runtime_root.to_path_buf(),
        })
    }

    /// Revalidates peer identity, committed journals, installed files and daemon image.
    #[must_use]
    pub fn revalidate_for_authenticated_desktop_peer(&self, stream: &UnixStream) -> bool {
        linux_stage("capability_revalidate_policy");
        let Some(policy) = compiled_policy() else {
            return false;
        };
        linux_stage("capability_revalidate_trust");
        let Some(trust) = crate::CompiledUpdateTrustRootV2::load()
            .map(runne_api::CompiledUpdateTrustRootV2::into_trust_root)
        else {
            return false;
        };
        linux_stage("capability_revalidate_time");
        let Some(now) = now() else {
            return false;
        };
        linux_stage("capability_revalidate_admission");
        let Some(fresh) = refresh_linux_admission(
            &self.profile_directory,
            &self.runtime_root,
            &self.paths,
            &trust,
            &policy,
            &self.admission,
            now,
        ) else {
            return false;
        };
        fresh == self.admission
            && valid_profile_runtime_pair(&self.profile_directory, &self.runtime_root)
            && self
                .paths
                .confirm_current_daemon(self.admission.daemon_sha256, &self.runtime_root)
                .is_ok()
            && self
                .paths
                .confirm_authenticated_peer(&self.peer, stream)
                .is_ok()
    }

    /// Returns fresh signed tuple measurements for the active V3 peer exchange.
    #[must_use]
    pub fn measurement_facts(
        &self,
        stream: &UnixStream,
    ) -> Option<VerifiedInstalledLinuxEnrollmentMeasurementFacts> {
        linux_stage("capability_measurement");
        if !self.revalidate_for_authenticated_desktop_peer(stream) {
            return None;
        }
        let [desktop, writer, daemon, contract] = self.paths.measure().ok()?.role_digests()?;
        let facts = VerifiedInstalledLinuxEnrollmentMeasurementFacts::from_admission(
            [desktop, writer, daemon, contract],
            &self.admission,
        )?;
        linux_stage("capability_measurement_facts");
        self.paths
            .confirm_authenticated_peer(&self.peer, stream)
            .ok()?;
        if !self.revalidate_for_authenticated_desktop_peer(stream) {
            return None;
        }
        Some(facts)
    }
}

/// Opaque measured Linux release evidence for one authenticated V3 peer exchange.
pub struct VerifiedInstalledLinuxEnrollmentMeasurementFacts {
    desktop: [u8; 32],
    writer: [u8; 32],
    daemon: [u8; 32],
    contract: [u8; 32],
    candidate_source: [u8; 32],
    target_manifest: [u8; 32],
    release_tuple: [u8; 32],
    qualification: [u8; 32],
    installed_generation: u64,
}

impl VerifiedInstalledLinuxEnrollmentMeasurementFacts {
    pub(super) fn from_admission(
        [desktop, writer, daemon, contract]: [[u8; 32]; 4],
        admission: &NativeEnrollmentTupleAdmission,
    ) -> Option<Self> {
        Some(Self {
            desktop,
            writer,
            daemon,
            contract,
            candidate_source: admission.candidate_source_sha256?,
            target_manifest: admission.target_manifest_sha256?,
            release_tuple: admission.release_tuple_sha256,
            qualification: admission
                .qualification
                .retained_qualification_binding_digest()?,
            installed_generation: admission.installed_generation,
        })
    }

    #[must_use]
    pub const fn desktop(&self) -> [u8; 32] {
        self.desktop
    }
    #[must_use]
    pub const fn writer(&self) -> [u8; 32] {
        self.writer
    }
    #[must_use]
    pub const fn daemon(&self) -> [u8; 32] {
        self.daemon
    }
    #[must_use]
    pub const fn contract(&self) -> [u8; 32] {
        self.contract
    }
    #[must_use]
    pub const fn candidate_source(&self) -> [u8; 32] {
        self.candidate_source
    }
    #[must_use]
    pub const fn target_manifest(&self) -> [u8; 32] {
        self.target_manifest
    }
    #[must_use]
    pub const fn release_tuple(&self) -> [u8; 32] {
        self.release_tuple
    }
    #[must_use]
    pub const fn qualification(&self) -> [u8; 32] {
        self.qualification
    }
    #[must_use]
    pub const fn installed_generation(&self) -> u64 {
        self.installed_generation
    }
}

fn valid_owner_private_directory(path: &Path) -> bool {
    let Ok(canonical) = path.canonicalize() else {
        return false;
    };
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    canonical == path
        && metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode().trailing_zeros() >= 6
}

fn valid_profile_runtime_pair(profile_directory: &Path, runtime_root: &Path) -> bool {
    runtime_root
        .file_name()
        .is_some_and(|name| name == "bundled-runtime")
        && runtime_root.parent() == Some(profile_directory)
        && valid_owner_private_directory(profile_directory)
        && valid_owner_private_directory(runtime_root)
}

fn now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
#[path = "linux_writer_capability_tests.rs"]
mod tests;
