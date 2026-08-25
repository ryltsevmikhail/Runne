use std::path::Path;

use super::{RootHandleBrokerError, VerifiedRootHandle, platform};

const MAX_EDITOR_PATH_BYTES: usize = 4096;

impl VerifiedRootHandle {
    /// Opens one existing Workspace-relative file with the OS default opener.
    ///
    /// The native backend validates the file from the admitted directory handle
    /// before deriving the short-lived target used by the platform opener.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection for traversal, links, directories, or an
    /// unavailable native opener.
    pub fn launch_system_default_editor(
        &self,
        relative_path: &str,
    ) -> Result<(), RootHandleBrokerError> {
        if !safe_editor_path(relative_path) {
            return Err(RootHandleBrokerError::Rejected);
        }
        platform::launch_system_default_editor(&self.handle, Path::new(relative_path))
    }
}

fn safe_editor_path(value: &str) -> bool {
    value.len() <= MAX_EDITOR_PATH_BYTES
        && !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte == 0 || byte < 0x20)
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
