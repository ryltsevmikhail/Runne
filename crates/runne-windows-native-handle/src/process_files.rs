use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BEGIN, FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, ReadFile, SetFilePointerEx,
};

use crate::directory_files::verify_regular_for_process;
use crate::identity::{DirectoryHandle, NativeHandleError, OwnedHandle};
use crate::path::ValidatedWindowsPath;
use crate::relative::open_relative_file;

const PATH_BUFFER_UNITS: usize = 32_768;
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Handle-relative executable and working-directory material for one launch.
///
/// The handles remain the source of identity. Paths are derived only for the
/// immediate Windows process-creation call and are never accepted from a
/// renderer or retained by the root admission layer.
pub struct ProcessFiles {
    _executable: OwnedHandle,
    _cwd: DirectoryHandle,
    executable_path: PathBuf,
    cwd_path: PathBuf,
    executable_content_digest: [u8; 32],
    executable_identity_digest: [u8; 32],
    cwd_identity_digest: [u8; 32],
}

impl DirectoryHandle {
    /// Opens an executable and cwd below this directory without following a
    /// reparse point or accepting traversal.
    ///
    /// # Errors
    ///
    /// Returns a closed error when either path is invalid, a reparse point is
    /// encountered, or native identity/content measurement fails.
    pub fn open_process_files(
        &self,
        executable: &Path,
        cwd: &Path,
    ) -> Result<ProcessFiles, NativeHandleError> {
        let executable_parts = ValidatedWindowsPath::relative(executable)?;
        let (name, parents) = executable_parts
            .split_last()
            .ok_or(NativeHandleError::Rejected)?;
        let parent = parents.iter().fold(PathBuf::new(), |mut path, part| {
            path.push(part);
            path
        });
        let parent_handle = if parents.is_empty() {
            self.try_clone()?
        } else {
            self.open_relative_directory(&parent)?
        };
        let executable = open_relative_file(parent_handle.owned_handle(), name)?;
        verify_regular_for_process(&executable)?;
        let cwd = self.open_relative_directory(cwd)?;
        let executable_path = final_path(&executable)?;
        let cwd_path = final_path(cwd.owned_handle())?;
        let executable_content_digest = content_digest(&executable)?;
        let executable_identity_digest = crate::regular_file::process_identity_digest(&executable)
            .map_err(|_| NativeHandleError::Unavailable)?;
        let cwd_identity_digest = cwd.identity().digest();
        Ok(ProcessFiles {
            _executable: executable,
            _cwd: cwd,
            executable_path,
            cwd_path,
            executable_content_digest,
            executable_identity_digest,
            cwd_identity_digest,
        })
    }
}

impl ProcessFiles {
    /// Returns the path derived from the still-open executable handle.
    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    /// Returns the path derived from the still-open cwd handle.
    #[must_use]
    pub fn cwd_path(&self) -> &Path {
        &self.cwd_path
    }

    /// Returns the executable content digest measured from the open handle.
    #[must_use]
    pub const fn executable_content_digest(&self) -> [u8; 32] {
        self.executable_content_digest
    }

    /// Returns the executable stable identity digest.
    #[must_use]
    pub const fn executable_identity_digest(&self) -> [u8; 32] {
        self.executable_identity_digest
    }

    /// Returns the cwd stable identity digest.
    #[must_use]
    pub const fn cwd_identity_digest(&self) -> [u8; 32] {
        self.cwd_identity_digest
    }
}

fn final_path(handle: &OwnedHandle) -> Result<PathBuf, NativeHandleError> {
    let mut buffer = vec![0_u16; PATH_BUFFER_UNITS];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            handle.raw(),
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).map_err(|_| NativeHandleError::Rejected)?,
            FILE_NAME_NORMALIZED,
        )
    };
    let length = usize::try_from(length).map_err(|_| NativeHandleError::Rejected)?;
    if length == 0 || length >= buffer.len() {
        return Err(NativeHandleError::Unavailable);
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn final_path_for_editor(handle: &OwnedHandle) -> Result<PathBuf, NativeHandleError> {
    final_path(handle)
}

fn content_digest(handle: &OwnedHandle) -> Result<[u8; 32], NativeHandleError> {
    let copy = handle.try_clone()?;
    let mut position = 0_i64;
    if unsafe { SetFilePointerEx(copy.raw(), 0, &raw mut position, FILE_BEGIN) } == 0 {
        return Err(NativeHandleError::Unavailable);
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; READ_BUFFER_BYTES];
    loop {
        let mut read = 0_u32;
        let ok = unsafe {
            ReadFile(
                copy.raw(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| NativeHandleError::Rejected)?,
                &raw mut read,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(NativeHandleError::Unavailable);
        }
        let read = usize::try_from(read).map_err(|_| NativeHandleError::Rejected)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}
