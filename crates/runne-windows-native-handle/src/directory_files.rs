use std::ffi::{OsStr, OsString};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStringExt;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_ID_BOTH_DIR_INFO, FILE_STANDARD_INFO, FileAttributeTagInfo, FileIdBothDirectoryInfo,
    FileStandardInfo, GetFileInformationByHandleEx, ReadFile,
};

use crate::identity::{DirectoryHandle, NativeHandleError, OwnedHandle, verify_directory};
use crate::relative::{open_relative_component, open_relative_file};

const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDirectoryEntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDirectoryEntry {
    name: OsString,
    kind: NativeDirectoryEntryKind,
    size_bytes: u64,
}

impl NativeDirectoryEntry {
    #[must_use]
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    #[must_use]
    pub const fn kind(&self) -> NativeDirectoryEntryKind {
        self.kind
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

impl DirectoryHandle {
    /// Lists bounded direct children without resolving names outside this handle.
    ///
    /// # Errors
    ///
    /// Returns a closed native error for malformed directory records, reparse points,
    /// unsupported objects, or native I/O failures.
    pub fn list_entries(
        &self,
        limit: usize,
    ) -> Result<Vec<NativeDirectoryEntry>, NativeHandleError> {
        enumerate(self.owned_handle(), limit)
    }

    /// Lists bounded direct children below this handle-relative directory.
    ///
    /// # Errors
    ///
    /// Returns a closed native error for traversal, malformed records, reparse points,
    /// unsupported objects, or native I/O failures.
    pub fn list_relative_entries(
        &self,
        path: &std::path::Path,
        limit: usize,
    ) -> Result<Vec<NativeDirectoryEntry>, NativeHandleError> {
        let directory = self.open_relative_directory(path)?;
        directory.list_entries(limit)
    }

    /// Reads bounded bytes from one handle-relative regular file.
    ///
    /// # Errors
    ///
    /// Returns a closed native error for traversal, reparse points, oversize content,
    /// unsupported objects, or native I/O failures.
    pub fn read_relative_file(
        &self,
        path: &std::path::Path,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, NativeHandleError> {
        let components = crate::path::ValidatedWindowsPath::relative(path)?;
        let (name, parents) = components.split_last().ok_or(NativeHandleError::Rejected)?;
        let parent_path = parents
            .iter()
            .fold(std::path::PathBuf::new(), |mut path, part| {
                path.push(part);
                path
            });
        let parent = if parents.is_empty() {
            self.try_clone()?
        } else {
            self.open_relative_directory(&parent_path)?
        };
        let file = open_relative_file(parent.owned_handle(), name)?;
        verify_regular_for_process(&file)?;
        read_bounded(&file, maximum_bytes)
    }
}

fn enumerate(
    directory: &OwnedHandle,
    limit: usize,
) -> Result<Vec<NativeDirectoryEntry>, NativeHandleError> {
    if limit == 0 {
        return Err(NativeHandleError::Rejected);
    }
    let mut buffer = vec![0_u8; DIRECTORY_BUFFER_BYTES];
    // SAFETY: the handle is an owned directory and the buffer is writable for this call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            directory.raw(),
            FileIdBothDirectoryInfo,
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).unwrap(),
        )
    };
    if ok == 0 {
        // An empty directory is reported as ERROR_NO_MORE_FILES by this information class.
        return (unsafe { GetLastError() } == ERROR_NO_MORE_FILES)
            .then_some(Vec::new())
            .ok_or(NativeHandleError::Unavailable);
    }
    let mut entries = Vec::new();
    let mut offset = 0_usize;
    loop {
        let entry = parse_entry(&buffer, offset)?;
        let is_directory = entry.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if entry.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(NativeHandleError::Rejected);
        }
        let name = entry.name;
        if name != OsStr::new(".") && name != OsStr::new("..") {
            if entries.len() >= limit {
                return Err(NativeHandleError::Rejected);
            }
            if is_directory {
                let child = open_relative_component(directory, &name)?;
                verify_directory(&child)?;
            } else {
                let child = open_relative_file(directory, &name)?;
                verify_regular_for_process(&child)?;
            }
            entries.push(NativeDirectoryEntry {
                name,
                kind: if is_directory {
                    NativeDirectoryEntryKind::Directory
                } else {
                    NativeDirectoryEntryKind::File
                },
                size_bytes: entry.size_bytes,
            });
        }
        if entry.next_offset == 0 {
            break;
        }
        let next = usize::try_from(entry.next_offset).map_err(|_| NativeHandleError::Rejected)?;
        if next < offset_of!(FILE_ID_BOTH_DIR_INFO, FileName) || offset.checked_add(next).is_none()
        {
            return Err(NativeHandleError::Rejected);
        }
        offset += next;
        if offset >= buffer.len() {
            return Err(NativeHandleError::Rejected);
        }
    }
    Ok(entries)
}

struct ParsedEntry {
    next_offset: u32,
    file_attributes: u32,
    size_bytes: u64,
    name: OsString,
}

fn parse_entry(buffer: &[u8], offset: usize) -> Result<ParsedEntry, NativeHandleError> {
    let header_end = offset
        .checked_add(offset_of!(FILE_ID_BOTH_DIR_INFO, FileName))
        .ok_or(NativeHandleError::Rejected)?;
    if header_end > buffer.len() {
        return Err(NativeHandleError::Rejected);
    }
    // SAFETY: the complete fixed header was bounds-checked; unaligned access is intentional.
    let entry =
        unsafe { ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<FILE_ID_BOTH_DIR_INFO>()) };
    if entry.FileNameLength % 2 != 0 {
        return Err(NativeHandleError::Rejected);
    }
    let name_bytes =
        usize::try_from(entry.FileNameLength).map_err(|_| NativeHandleError::Rejected)?;
    let name_start = header_end;
    let name_end = name_start
        .checked_add(name_bytes)
        .ok_or(NativeHandleError::Rejected)?;
    if name_end > buffer.len() || entry.EndOfFile < 0 {
        return Err(NativeHandleError::Rejected);
    }
    let name_units = name_bytes / size_of::<u16>();
    // SAFETY: the UTF-16 name range was bounds-checked and consists of u16 units.
    let name = unsafe {
        OsString::from_wide(std::slice::from_raw_parts(
            buffer.as_ptr().add(name_start).cast(),
            name_units,
        ))
    };
    if name.is_empty()
        || name
            .to_string_lossy()
            .chars()
            .any(|character| character == '/' || character == '\\')
    {
        return Err(NativeHandleError::Rejected);
    }
    Ok(ParsedEntry {
        next_offset: entry.NextEntryOffset,
        file_attributes: entry.FileAttributes,
        size_bytes: u64::try_from(entry.EndOfFile).map_err(|_| NativeHandleError::Rejected)?,
        name,
    })
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn verify_regular_for_process(handle: &OwnedHandle) -> Result<(), NativeHandleError> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: each output buffer has its exact native structure size.
    let attributes_ok = unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileAttributeTagInfo,
            (&raw mut attributes).cast(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap(),
        )
    };
    // SAFETY: each output buffer has its exact native structure size.
    let standard_ok = unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileStandardInfo,
            (&raw mut standard).cast(),
            u32::try_from(size_of::<FILE_STANDARD_INFO>()).unwrap(),
        )
    };
    (attributes_ok != 0
        && standard_ok != 0
        && attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            == 0)
        .then_some(())
        .ok_or(NativeHandleError::Rejected)
}

fn read_bounded(handle: &OwnedHandle, maximum_bytes: usize) -> Result<Vec<u8>, NativeHandleError> {
    let requested = maximum_bytes
        .checked_add(1)
        .ok_or(NativeHandleError::Rejected)?;
    let requested_u32 = u32::try_from(requested).map_err(|_| NativeHandleError::Rejected)?;
    let mut bytes = vec![0_u8; requested];
    let mut read = 0_u32;
    // SAFETY: the buffer is valid for the requested byte count and the handle is synchronous.
    let ok = unsafe {
        ReadFile(
            handle.raw(),
            bytes.as_mut_ptr(),
            requested_u32,
            &raw mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(NativeHandleError::Unavailable);
    }
    let read = usize::try_from(read).map_err(|_| NativeHandleError::Rejected)?;
    if read > maximum_bytes {
        return Err(NativeHandleError::Rejected);
    }
    bytes.truncate(read);
    Ok(bytes)
}
