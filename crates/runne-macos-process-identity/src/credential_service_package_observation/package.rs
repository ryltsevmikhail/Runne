use std::fs::File;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use runne_api::NativeEnrollmentTupleV3Digests;

use crate::packaged_writer_observation::artifact::{ArtifactSnapshot, RetainedArtifact};
use crate::packaged_writer_observation::package::{
    DirectorySnapshot, directory_snapshot, open_absolute_directory, open_rooted_file, valid_root,
};

use super::MacOsCredentialServicePackageObservationError;
use super::layout::{CANDIDATE_MAX_BYTES, ENTRIES, ENTRY_COUNT, Entry, rooted_path};

mod entries;

use entries::capture_entries;

pub(super) struct ServicePackage {
    application: PathBuf,
    root: File,
    root_identity: DirectorySnapshot,
    entries: [RetainedArtifact; ENTRY_COUNT],
}

impl ServicePackage {
    pub(super) fn capture(
        application: &Path,
    ) -> Result<Self, MacOsCredentialServicePackageObservationError> {
        let root = open_absolute_directory(application).map_err(map)?;
        let root_identity = directory_snapshot(&root).map_err(map)?;
        valid_root(&root_identity)
            .then_some(())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        let entries = capture_entries(&root, &root_identity)?;
        let package = Self {
            application: application.to_path_buf(),
            root,
            root_identity,
            entries,
        };
        package.revalidate()?;
        Ok(package)
    }

    pub(super) fn revalidate(&self) -> Result<(), MacOsCredentialServicePackageObservationError> {
        let fresh_root = open_absolute_directory(&self.application).map_err(map)?;
        (directory_snapshot(&self.root).map_err(map)? == self.root_identity
            && directory_snapshot(&fresh_root).map_err(map)? == self.root_identity)
            .then_some(())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        let fresh_entries = capture_entries(&fresh_root, &self.root_identity)?;
        for retained in &self.entries {
            retained.revalidate().map_err(map)?;
        }
        for (retained, fresh) in self.entries.iter().zip(fresh_entries.iter()) {
            retained
                .matches(fresh)
                .then_some(())
                .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        }
        for (index, retained) in self.entries.iter().enumerate() {
            if self.entries[..index]
                .iter()
                .any(|other| other.same_vnode(retained))
            {
                return Err(MacOsCredentialServicePackageObservationError::Rejected);
            }
        }
        Ok(())
    }

    pub(super) fn require_service_locator(
        &self,
        main_executable: &Path,
    ) -> Result<(), MacOsCredentialServicePackageObservationError> {
        (main_executable == self.path(ENTRIES[4]))
            .then_some(())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        let fresh = open_rooted_file(&self.root, &self.root_identity, ENTRIES[4].components)
            .map_err(map)?;
        (ArtifactSnapshot::from_file_for_match(&fresh).map_err(map)? == *self.entries[4].snapshot())
            .then_some(())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)
    }

    pub(super) fn release_digests(
        &self,
        candidate_binding: &[u8],
    ) -> Result<NativeEnrollmentTupleV3Digests, MacOsCredentialServicePackageObservationError> {
        let digest = |index: usize| encode(self.entries[index].digest());
        Ok(NativeEnrollmentTupleV3Digests {
            candidate_sha256: encode(&candidate_digest(candidate_binding)?),
            desktop_sha256: digest(1),
            writer_sha256: digest(2),
            daemon_sha256: digest(3),
            credential_service_sha256: digest(4),
            launch_agent_plist_sha256: digest(5),
            entitlements_sha256: digest(6),
            provisioning_sha256: digest(7),
            xpc_protocol_sha256: digest(8),
            contract_sha256: digest(9),
        })
    }

    pub(super) fn candidate_binding(
        &self,
    ) -> Result<Vec<u8>, MacOsCredentialServicePackageObservationError> {
        read_bounded(&self.entries[0], CANDIDATE_MAX_BYTES)
    }

    pub(super) const fn service_artifact(&self) -> &RetainedArtifact {
        &self.entries[4]
    }

    pub(super) fn static_paths(&self) -> [PathBuf; 4] {
        [
            self.path(ENTRIES[1]),
            self.path(ENTRIES[2]),
            self.path(ENTRIES[3]),
            self.path(ENTRIES[4]),
        ]
    }

    fn path(&self, entry: Entry) -> PathBuf {
        rooted_path(&self.application, entry)
    }
}

fn read_bounded(
    artifact: &RetainedArtifact,
    maximum: u64,
) -> Result<Vec<u8>, MacOsCredentialServicePackageObservationError> {
    let length = artifact.snapshot().length();
    if length > maximum {
        return Err(MacOsCredentialServicePackageObservationError::Rejected);
    }
    let mut bytes = vec![
        0_u8;
        usize::try_from(length)
            .map_err(|_| MacOsCredentialServicePackageObservationError::Rejected)?
    ];
    let file = artifact.file_for_read();
    let read = file
        .read_at(&mut bytes, 0)
        .map_err(|_| MacOsCredentialServicePackageObservationError::Rejected)?;
    if read != bytes.len()
        || file
            .read_at(&mut [0_u8; 1], length)
            .map_err(|_| MacOsCredentialServicePackageObservationError::Rejected)?
            != 0
    {
        return Err(MacOsCredentialServicePackageObservationError::Rejected);
    }
    artifact.revalidate().map_err(map)?;
    Ok(bytes)
}

fn candidate_digest(
    candidate_binding: &[u8],
) -> Result<[u8; 32], MacOsCredentialServicePackageObservationError> {
    const PREFIX: &[u8] = b"\"releaseCandidateSha256\":\"";
    let Some(index) = candidate_binding
        .windows(PREFIX.len())
        .position(|window| window == PREFIX)
    else {
        return Err(MacOsCredentialServicePackageObservationError::Rejected);
    };
    let start = index + PREFIX.len();
    let end = start + 64;
    let Some(value) = candidate_binding.get(start..end) else {
        return Err(MacOsCredentialServicePackageObservationError::Rejected);
    };
    if candidate_binding.get(end) != Some(&b'"') {
        return Err(MacOsCredentialServicePackageObservationError::Rejected);
    }
    let mut digest = [0_u8; 32];
    std::str::from_utf8(value)
        .is_ok_and(|value| decode_hex(value, &mut digest))
        .then_some(digest)
        .ok_or(MacOsCredentialServicePackageObservationError::Rejected)
}

fn encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn decode_hex(value: &str, destination: &mut [u8; 32]) -> bool {
    if value.len() != 64 {
        return false;
    }
    for (index, byte) in destination.iter_mut().enumerate() {
        let Some(high) = value
            .as_bytes()
            .get(index * 2)
            .and_then(|value| hex_digit(*value))
        else {
            return false;
        };
        let Some(low) = value
            .as_bytes()
            .get(index * 2 + 1)
            .and_then(|value| hex_digit(*value))
        else {
            return false;
        };
        *byte = high << 4 | low;
    }
    true
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

const fn map(
    error: crate::MacOsPackagedWriterObservationError,
) -> MacOsCredentialServicePackageObservationError {
    match error {
        crate::MacOsPackagedWriterObservationError::Rejected => {
            MacOsCredentialServicePackageObservationError::Rejected
        }
        crate::MacOsPackagedWriterObservationError::Unavailable => {
            MacOsCredentialServicePackageObservationError::Unavailable
        }
    }
}
