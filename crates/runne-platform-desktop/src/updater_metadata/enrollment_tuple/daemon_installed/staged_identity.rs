use std::path::Path;

use super::{
    DaemonIdentityVerifier, NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleAdmission,
};

/// Daemon self identity anchored to the authenticated launch runtime root.
pub(crate) struct CurrentStagedDaemonIdentity<'a> {
    runtime_root: &'a Path,
}

impl<'a> CurrentStagedDaemonIdentity<'a> {
    pub(crate) const fn new(runtime_root: &'a Path) -> Self {
        Self { runtime_root }
    }
}

impl DaemonIdentityVerifier for CurrentStagedDaemonIdentity<'_> {
    fn confirm(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
        admission: &NativeEnrollmentTupleAdmission,
    ) -> bool {
        admission
            .macos_daemon_code_identity
            .as_ref()
            .is_some_and(|identity| {
                paths
                    .confirm_current_staged_daemon(
                        self.runtime_root,
                        admission.daemon_sha256,
                        identity,
                    )
                    .is_ok()
            })
    }
}
