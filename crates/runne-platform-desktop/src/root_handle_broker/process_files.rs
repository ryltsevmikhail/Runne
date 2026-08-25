use std::path::Path;

use super::{RootHandleBrokerError, VerifiedRootHandle, platform};

pub struct NativeProcessFiles {
    inner: platform::NativeProcessFiles,
}

impl NativeProcessFiles {
    #[must_use]
    pub fn executable_command_path(&self) -> std::path::PathBuf {
        platform::executable_command_path(&self.inner)
    }

    #[must_use]
    pub fn cwd_command_path(&self) -> std::path::PathBuf {
        platform::cwd_command_path(&self.inner)
    }

    #[must_use]
    pub const fn executable_content_digest(&self) -> [u8; 32] {
        platform::executable_content_digest(&self.inner)
    }

    #[must_use]
    pub const fn executable_filesystem_identity_digest(&self) -> [u8; 32] {
        platform::executable_filesystem_identity_digest(&self.inner)
    }

    #[must_use]
    pub const fn cwd_filesystem_identity_digest(&self) -> [u8; 32] {
        platform::cwd_filesystem_identity_digest(&self.inner)
    }
}

impl VerifiedRootHandle {
    /// Opens executable and working-directory handles below this root.
    ///
    /// The returned material contains no user path and is intended for one
    /// owner-bound native launch preparation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for traversal, links, wrong object kinds, or I/O.
    pub fn open_process_files(
        &self,
        executable: &Path,
        cwd: &Path,
    ) -> Result<NativeProcessFiles, RootHandleBrokerError> {
        Ok(NativeProcessFiles {
            inner: platform::open_process_files(&self.handle, executable, cwd)?,
        })
    }
}
