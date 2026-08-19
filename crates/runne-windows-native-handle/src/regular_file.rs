use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo,
    FileIdInfo, FileStandardInfo, FlushFileBuffers, GetFileInformationByHandleEx,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING,
};

use crate::identity::OwnedHandle;

/// Redacted failures from the audited regular-file boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFileError {
    Rejected,
    DestinationExists,
    Unavailable,
}

impl fmt::Display for NativeFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("native regular file operation rejected")
    }
}

impl std::error::Error for NativeFileError {}

/// ReFS-safe stable identity, never inferred from a path string.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RegularFileId {
    volume_serial: u64,
    file_id: [u8; 16],
}

impl fmt::Debug for RegularFileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegularFileId(<redacted>)")
    }
}

/// A file identity paired with its currently observed hard-link count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegularFileSnapshot {
    id: RegularFileId,
    link_count: u32,
}

impl RegularFileSnapshot {
    #[must_use]
    pub const fn id(self) -> RegularFileId {
        self.id
    }

    #[must_use]
    pub const fn link_count(self) -> u32 {
        self.link_count
    }
}

/// Opens and inspects a regular, non-reparse file without exposing its handle.
///
/// # Errors
///
/// Returns a redacted error when the path is unsafe, missing, or cannot be inspected.
pub fn inspect_regular_file(path: &Path) -> Result<RegularFileSnapshot, NativeFileError> {
    snapshot(&open(path, FILE_READ_ATTRIBUTES)?)
}

/// Flushes a file only after confirming its stable identity did not change.
///
/// # Errors
///
/// Returns a redacted error when the file cannot be reopened, inspected, or flushed safely.
pub fn sync_regular_file(path: &Path, expected: RegularFileId) -> Result<(), NativeFileError> {
    let handle = open(path, FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES)?;
    if snapshot(&handle)?.id != expected {
        return Err(NativeFileError::Rejected);
    }
    // SAFETY: the owned handle names the verified regular file and remains live for this call.
    if unsafe { FlushFileBuffers(handle.raw()) } == 0 {
        return Err(NativeFileError::Unavailable);
    }
    (snapshot(&handle)?.id == expected)
        .then_some(())
        .ok_or(NativeFileError::Rejected)
}

/// Publishes a private temporary file exactly once, without copy or replacement.
///
/// # Errors
///
/// Returns a redacted error when either path is unsafe, the destination exists, or the move
/// cannot be durably completed with the expected identity.
pub fn move_regular_file_no_replace_write_through(
    temporary: &Path,
    final_path: &Path,
    expected: RegularFileId,
) -> Result<(), NativeFileError> {
    let source = inspect_regular_file(temporary)?;
    if source.id != expected || source.link_count != 1 {
        return Err(NativeFileError::Rejected);
    }
    match std::fs::symlink_metadata(final_path) {
        Ok(_) => return Err(NativeFileError::DestinationExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(NativeFileError::Unavailable),
    }
    let temporary = wide(temporary)?;
    let final_wide = wide(final_path)?;
    // SAFETY: both UTF-16 buffers are NUL-terminated for this synchronous system call.
    if unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            final_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(move_error());
    }
    let final_snapshot = inspect_regular_file(final_path)?;
    if final_snapshot.id != expected || final_snapshot.link_count != 1 {
        return Err(NativeFileError::Rejected);
    }
    Ok(())
}

fn open(path: &Path, access: u32) -> Result<OwnedHandle, NativeFileError> {
    let path = wide(path)?;
    // SAFETY: the input buffer is NUL-terminated for the duration of this call.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    OwnedHandle::new(handle).map_err(|_| NativeFileError::Unavailable)
}

fn snapshot(handle: &OwnedHandle) -> Result<RegularFileSnapshot, NativeFileError> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let mut file_id = FILE_ID_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: each output has the exact size required by its information class.
    let attributes_ok = unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileAttributeTagInfo,
            (&raw mut attributes).cast(),
            size::<FILE_ATTRIBUTE_TAG_INFO>(),
        )
    };
    // SAFETY: each output has the exact size required by its information class.
    let id_ok = unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileIdInfo,
            (&raw mut file_id).cast(),
            size::<FILE_ID_INFO>(),
        )
    };
    // SAFETY: each output has the exact size required by its information class.
    let standard_ok = unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileStandardInfo,
            (&raw mut standard).cast(),
            size::<FILE_STANDARD_INFO>(),
        )
    };
    if attributes_ok == 0
        || id_ok == 0
        || standard_ok == 0
        || attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        || file_id.VolumeSerialNumber == 0
        || file_id.FileId.Identifier == [0; 16]
        || standard.NumberOfLinks == 0
    {
        return Err(NativeFileError::Rejected);
    }
    Ok(RegularFileSnapshot {
        id: RegularFileId {
            volume_serial: file_id.VolumeSerialNumber,
            file_id: file_id.FileId.Identifier,
        },
        link_count: standard.NumberOfLinks,
    })
}

fn wide(path: &Path) -> Result<Vec<u16>, NativeFileError> {
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.is_empty() || value.contains(&0) {
        return Err(NativeFileError::Rejected);
    }
    value.push(0);
    Ok(value)
}

fn size<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).unwrap()
}

fn move_error() -> NativeFileError {
    // SAFETY: this reads the error immediately after the failed system call.
    match unsafe { GetLastError() } {
        ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => NativeFileError::DestinationExists,
        _ => NativeFileError::Unavailable,
    }
}
