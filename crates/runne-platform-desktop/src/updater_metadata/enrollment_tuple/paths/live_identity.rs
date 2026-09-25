use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError};

impl NativeEnrollmentArtifactPathsV1 {
    #[cfg(target_os = "macos")]
    pub(super) fn verify_live_desktop(&self) -> Result<(), NativeEnrollmentTupleError> {
        if !self.live_desktop {
            return Ok(());
        }
        self.desktop_file.confirm_current_executable()
    }

    #[cfg(target_os = "macos")]
    pub(in crate::updater_metadata) fn verify_live_daemon(
        &self,
    ) -> Result<(), NativeEnrollmentTupleError> {
        let pid = std::num::NonZeroU32::new(std::process::id())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        let executable =
            std::env::current_exe().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        runne_macos_process_identity::MacOsProcessExecutableIdentity::observe(pid, &executable)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?
            .matches_file(self.daemon_file.metadata())
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn verify_live_desktop(&self) -> Result<(), NativeEnrollmentTupleError> {
        if !self.live_desktop {
            return Ok(());
        }
        let before = crate::provider_credential_broker::observe_current_process_start()
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let current = std::fs::File::open("/proc/self/exe")
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !self.desktop_file.matches_file(&current)?
            || std::fs::canonicalize(
                std::env::current_exe().map_err(|_| NativeEnrollmentTupleError::Rejected)?,
            )
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?
                != self.desktop
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let after = crate::provider_credential_broker::observe_current_process_start()
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        (before == after && before != [0; 32])
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub(super) fn verify_live_desktop(&self) -> Result<(), NativeEnrollmentTupleError> {
        (!self.live_desktop)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }
}
