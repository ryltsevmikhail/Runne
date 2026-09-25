use std::os::unix::net::UnixStream;

use super::super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError};
use super::LinuxAuthenticatedDesktopPeer;

impl NativeEnrollmentArtifactPathsV1 {
    pub(in crate::updater_metadata) fn confirm_daemon_process(
        &self,
        pid: u32,
        start_ticks: u64,
    ) -> Result<(), NativeEnrollmentTupleError> {
        if pid == 0 || start_ticks == 0 || super::process_start_ticks(pid)? != start_ticks {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let executable = std::fs::File::open(format!("/proc/{pid}/exe"))
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        self.daemon_file
            .matches_file(&executable)?
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        (super::process_start_ticks(pid)? == start_ticks)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    pub(in crate::updater_metadata) fn confirm_current_daemon(
        &self,
    ) -> Result<(), NativeEnrollmentTupleError> {
        let before = super::process_start_ticks(std::process::id())?;
        let executable = std::fs::File::open("/proc/self/exe")
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !self.daemon_file.matches_file(&executable)? {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let after = super::process_start_ticks(std::process::id())?;
        (before == after)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
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
