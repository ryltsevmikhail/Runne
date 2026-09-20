use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use crate::{DatabaseFileIdentity, IdentityError};

#[cfg(test)]
#[path = "windows_identity_tests.rs"]
mod windows_identity_tests;

/// Measures a single-linked regular file at the supplied path.
///
/// # Errors
/// Rejects missing, nonregular, multiply-linked or invalid file identities.
pub fn path_database_identity(path: &Path) -> Result<DatabaseFileIdentity, IdentityError> {
    identity(
        std::fs::File::open(path)
            .map_err(|_| IdentityError)?
            .as_raw_handle()
            .cast(),
    )
}

/// Measures the retained file handle without reopening a pathname.
///
/// This can bind an exclusive-create witness to `SQLite`'s independently
/// measured main-file handle. It does not prove ownership, permissions or
/// `SQLite` validity.
///
/// # Errors
/// Rejects nonregular, multiply-linked or invalid file identities.
pub fn file_database_identity(file: &File) -> Result<DatabaseFileIdentity, IdentityError> {
    identity(file.as_raw_handle().cast())
}

/// Measures the exact main file `SQLite` currently holds open, never a fresh
/// path lookup: the win32 VFS publishes its own `HANDLE` through
/// `SQLITE_FCNTL_WIN32_GET_HANDLE`.
///
/// # Errors
/// Returns an error unless `SQLite` reveals its exact opened Win32 main-file
/// handle with a stable single-linked file id.
pub fn opened_database_identity(
    connection: &rusqlite::Connection,
) -> Result<DatabaseFileIdentity, IdentityError> {
    if !exact_sqlite() {
        return Err(IdentityError);
    }
    let mut handle: *mut c_void = std::ptr::null_mut();
    // SAFETY: the win32 VFS writes one borrowed HANDLE for this synchronous call.
    let status = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
            std::ptr::addr_of_mut!(handle).cast(),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK || handle.is_null() {
        return Err(IdentityError);
    }
    identity(handle)
}

/// Measures the journal (or write-ahead log) file `SQLite` currently holds open.
///
/// A null journal pointer or missing public methods is rejected, so the only
/// success shape is a measured, single-linked journal file identity.
///
/// # Errors
/// Returns an error when the journal pointer cannot be revealed or its handle
/// cannot be inspected; unsupported engines and `NULL_IO` handles fail closed.
pub fn opened_journal_identity(
    connection: &rusqlite::Connection,
) -> Result<Option<DatabaseFileIdentity>, IdentityError> {
    if !exact_sqlite() {
        return Err(IdentityError);
    }
    let mut journal = std::ptr::null_mut::<rusqlite::ffi::sqlite3_file>();
    // SAFETY: SQLite writes one borrowed journal pointer for this call.
    let status = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_JOURNAL_POINTER,
            std::ptr::addr_of_mut!(journal).cast(),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(IdentityError);
    }
    // SAFETY: the journal pointer is live for this synchronous call and
    // pMethods is public `SQLite` ABI data.
    let Some(control) = (unsafe {
        journal
            .as_ref()
            .and_then(|file| file.pMethods.as_ref())
            .and_then(|methods| methods.xFileControl)
    }) else {
        return Err(IdentityError);
    };
    let mut handle: *mut c_void = std::ptr::null_mut();
    // SAFETY: the journal's own xFileControl writes its Win32 HANDLE here.
    let status = unsafe {
        control(
            journal,
            rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
            std::ptr::addr_of_mut!(handle).cast(),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK || handle.is_null() {
        return Err(IdentityError);
    }
    identity(handle).map(Some)
}

fn exact_sqlite() -> bool {
    // SAFETY: SQLite owns its source-id static string.
    let source = unsafe { rusqlite::ffi::sqlite3_sourceid() };
    if source.is_null() {
        return false;
    }
    // SAFETY: checked non-null and SQLite owns the NUL-terminated source id.
    let source = unsafe { std::ffi::CStr::from_ptr(source) };
    (unsafe { rusqlite::ffi::sqlite3_libversion_number() }) == 3_049_001
        && source.to_bytes() == b"2025-02-18 13:38:58 873d4e274b4988d260ba8354a9718324a1c26187a4ab4c1cc0227c03d0f10e70"
}

fn identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<DatabaseFileIdentity, IdentityError> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_ID_INFO, FILE_STANDARD_INFO, FileAttributeTagInfo, FileIdInfo, FileStandardInfo,
        GetFileInformationByHandleEx,
    };
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let mut id = FILE_ID_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    /* SAFETY: exact output buffers for each synchronous query. */
    let tags = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attributes).cast(),
            u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
                .map_err(|_| IdentityError)?,
        )
    };
    /* SAFETY: exact output buffers for each synchronous query. */
    let a = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut id).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).map_err(|_| IdentityError)?,
        )
    };
    /* SAFETY: exact output buffers for each synchronous query. */
    let b = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut standard).cast(),
            u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>()).map_err(|_| IdentityError)?,
        )
    };
    if tags == 0
        || a == 0
        || b == 0
        || attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
        || id.VolumeSerialNumber == 0
        || id.FileId.Identifier == [0; 16]
        || standard.NumberOfLinks != 1
    {
        return Err(IdentityError);
    }
    Ok(DatabaseFileIdentity {
        volume: id.VolumeSerialNumber,
        file: id.FileId.Identifier,
    })
}
