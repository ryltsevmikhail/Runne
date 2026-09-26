use std::os::unix::net::UnixStream;
use std::{
    fs::File,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

use super::super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError};
use super::LinuxAuthenticatedDesktopPeer;

impl NativeEnrollmentArtifactPathsV1 {
    pub(in crate::updater_metadata) fn confirm_daemon_process(
        &self,
        pid: u32,
        start_ticks: u64,
        launched_file: &File,
        runtime_root: &Path,
        expected_digest: [u8; 32],
    ) -> Result<(), NativeEnrollmentTupleError> {
        if pid == 0 || start_ticks == 0 || super::process_start_ticks(pid)? != start_ticks {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let executable = File::open(format!("/proc/{pid}/exe"))
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        self.verify_live_daemon_image(&executable, launched_file, runtime_root, expected_digest)?;
        let reopened = File::open(format!("/proc/{pid}/exe"))
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        executable_identity_matches(&executable, &reopened)?;
        (super::process_start_ticks(pid)? == start_ticks)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    pub(in crate::updater_metadata) fn confirm_current_daemon(
        &self,
        expected_digest: [u8; 32],
        runtime_root: &Path,
    ) -> Result<(), NativeEnrollmentTupleError> {
        let before = super::process_start_ticks(std::process::id())?;
        let retained_before = self.daemon_file.measure()?;
        if hex::decode(&retained_before).ok().as_deref() != Some(&expected_digest) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let executable = File::open("/proc/self/exe")
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        self.verify_live_daemon_image(&executable, &executable, runtime_root, expected_digest)?;
        let reopened = File::open("/proc/self/exe")
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        executable_identity_matches(&executable, &reopened)?;
        let retained_after = self.daemon_file.measure()?;
        let after = super::process_start_ticks(std::process::id())?;
        (before == after && retained_before == retained_after)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    fn verify_live_daemon_image(
        &self,
        live: &File,
        launched_file: &File,
        runtime_root: &Path,
        expected_digest: [u8; 32],
    ) -> Result<(), NativeEnrollmentTupleError> {
        let live_image = super::super::super::enrollment_measurement::OpenedNativeEnrollmentFile::new(
            live.try_clone().map_err(|_| NativeEnrollmentTupleError::Rejected)?,
        )?;
        let measured = live_image.measure()?;
        if hex::decode(measured).ok().as_deref() != Some(&expected_digest) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        executable_identity_matches(live, launched_file)?;
        let retained_digest = self.daemon_file.measure()?;
        if hex::decode(retained_digest).ok().as_deref() != Some(&expected_digest) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        if self.daemon_file.matches_file(live)? {
            return Ok(());
        }
        let length = self.daemon_file.metadata().len();
        let activation = runtime_root.join(".desktop-protected-activation");
        let stage = activation.join("executables-v1");
        require_private_directory(runtime_root)?;
        require_private_directory(&activation)?;
        require_private_directory(&stage)?;
        let expected = stage.join(format!("{}-{length}.runned", hex::encode(expected_digest)));
        if std::fs::canonicalize(&expected).ok().as_deref() != Some(expected.as_path()) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let staged = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(expected)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let staged = super::super::super::enrollment_measurement::OpenedNativeEnrollmentFile::new(staged)?;
        let metadata = staged.metadata();
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o500
            || metadata.nlink() != 1
            || !staged.matches_file(launched_file)?
            || !staged.matches_file(live)?
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        Ok(())
    }

    pub(in crate::updater_metadata) fn confirm_authenticated_peer(
        &self,
        peer: &LinuxAuthenticatedDesktopPeer,
        stream: &UnixStream,
    ) -> Result<(), NativeEnrollmentTupleError> {
        peer.revalidate(stream)?;
        let executable = std::fs::File::open(format!("/proc/{}/exe", peer.pid()))
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !self.desktop_file.matches_file(&executable)? {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        peer.revalidate(stream)
    }

    pub(in crate::updater_metadata) fn verified_linux_writer_artifact(
        &self,
        admission: &super::super::super::NativeEnrollmentTupleAdmission,
    ) -> Result<
        runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact,
        NativeEnrollmentTupleError,
    > {
        self.confirm_current()?;
        let writer_digest = self.writer_file.measure()?;
        if writer_digest != hex::encode(admission.writer_sha256) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let artifact =
            runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact::new(
                self.writer.clone(),
                admission.writer_sha256,
                admission.release_tuple_sha256,
            )
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        self.confirm_current()?;
        Ok(artifact)
    }
}

fn require_private_directory(path: &Path) -> Result<(), NativeEnrollmentTupleError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
        || std::fs::canonicalize(path).ok().as_deref() != Some(path)
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok(())
}

fn executable_identity_matches(first: &File, second: &File) -> Result<(), NativeEnrollmentTupleError> {
    let first = first.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let second = second.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    (first.dev() == second.dev() && first.ino() == second.ino())
        .then_some(())
        .ok_or(NativeEnrollmentTupleError::Rejected)
}
