use std::path::Path;

use super::{RootHandleBrokerError, VerifiedRootHandle, platform};

const MAX_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootFileKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootFileEntry {
    path: String,
    kind: RootFileKind,
    size_bytes: u64,
}

impl RootFileEntry {
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub const fn kind(&self) -> RootFileKind {
        self.kind
    }
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

impl VerifiedRootHandle {
    /// Lists one bounded directory at the verified root without path rebasing.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection for links, unsupported objects, or I/O failures.
    pub fn list_root(&self, limit: usize) -> Result<Vec<RootFileEntry>, RootHandleBrokerError> {
        (limit > 0)
            .then_some(())
            .ok_or(RootHandleBrokerError::Rejected)?;
        platform::list_root(&self.handle, limit)
    }

    /// Clones the verified native root handle without materializing its path.
    ///
    /// # Errors
    ///
    /// Returns a closed failure if the native handle cannot be duplicated or revalidated.
    pub fn try_clone(&self) -> Result<Self, RootHandleBrokerError> {
        platform::clone_root(self)
    }

    /// Lists one bounded directory below the verified root without path rebasing.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection for traversal, links, unsupported objects, or I/O failures.
    pub fn list_relative(
        &self,
        path: &str,
        limit: usize,
    ) -> Result<Vec<RootFileEntry>, RootHandleBrokerError> {
        let path = validate(path, true)?;
        (limit > 0)
            .then_some(())
            .ok_or(RootHandleBrokerError::Rejected)?;
        platform::list_relative(&self.handle, Path::new(path), limit)
    }

    /// Reads one bounded UTF-8 regular file below the verified root.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection for traversal, links, binary content, oversize, or I/O failures.
    pub fn read_text_relative(
        &self,
        path: &str,
        maximum_bytes: usize,
    ) -> Result<String, RootHandleBrokerError> {
        let path = validate(path, false)?;
        (maximum_bytes > 0)
            .then_some(())
            .ok_or(RootHandleBrokerError::Rejected)?;
        platform::read_text_relative(&self.handle, Path::new(path), maximum_bytes)
    }
}

fn validate(value: &str, allow_empty: bool) -> Result<&str, RootHandleBrokerError> {
    if value.len() > MAX_PATH_BYTES || (!allow_empty && value.is_empty()) {
        return Err(RootHandleBrokerError::Rejected);
    }
    // The empty path names the workspace root itself (list requests); every
    // non-empty path must be a clean handle-relative path.
    if !value.is_empty()
        && (value.starts_with('/')
            || value.contains('\\')
            || value.bytes().any(|byte| byte == 0 || byte < 0x20)
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."))
    {
        return Err(RootHandleBrokerError::Rejected);
    }
    Ok(value)
}

pub(super) const fn entry(path: String, kind: RootFileKind, size_bytes: u64) -> RootFileEntry {
    RootFileEntry {
        path,
        kind,
        size_bytes,
    }
}
