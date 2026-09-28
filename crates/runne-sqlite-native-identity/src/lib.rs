//! Audited native identity bridge for the exact `SQLite` main-file handle.
#[cfg(unix)]
mod trusted_vfs;
#[cfg(windows)]
mod windows_file;
#[cfg(unix)]
use std::{os::fd::FromRawFd, os::unix::fs::MetadataExt};
#[cfg(windows)]
pub use windows_file::{
    file_database_identity, opened_database_identity, opened_journal_identity,
    path_database_identity,
};
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseFileIdentity {
    device: u64,
    inode: u64,
}
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseFileIdentity {
    volume: u64,
    file: [u8; 16],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityError;
#[cfg(unix)]
#[repr(C)]
pub(crate) struct UnixFilePrefix {
    methods: *const rusqlite::ffi::sqlite3_io_methods,
    vfs: *mut rusqlite::ffi::sqlite3_vfs,
    inode: *mut std::ffi::c_void,
    descriptor: std::ffi::c_int,
}
#[cfg(unix)]
const _: () = assert!(std::mem::offset_of!(UnixFilePrefix, methods) == 0);
#[cfg(unix)]
const _: () = assert!(
    std::mem::offset_of!(UnixFilePrefix, vfs)
        == std::mem::size_of::<*const rusqlite::ffi::sqlite3_io_methods>()
);
#[cfg(unix)]
const _: () = assert!(
    std::mem::size_of::<UnixFilePrefix>()
        >= std::mem::offset_of!(UnixFilePrefix, descriptor)
            + std::mem::size_of::<std::ffi::c_int>()
);

#[cfg(unix)]
struct TrustedUnixConnection {
    vfs: *mut rusqlite::ffi::sqlite3_vfs,
    methods: *const rusqlite::ffi::sqlite3_io_methods,
}
#[cfg(unix)]
mod unix_file;
#[cfg(unix)]
pub use unix_file::{file_database_identity, path_database_identity};

#[cfg(unix)]
fn trusted_unix_connection(
    connection: &rusqlite::Connection,
) -> Option<(TrustedUnixConnection, *mut rusqlite::ffi::sqlite3_file)> {
    let trusted_builtin = trusted_vfs::trusted_builtin_vfs()?;
    let vfs = public_unix_vfs(connection, trusted_builtin)?;
    let mut file = std::ptr::null_mut::<rusqlite::ffi::sqlite3_file>();
    // SAFETY: pinned Unix VFS FILE_POINTER returns its live `unixFile` prefix.
    let status = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_FILE_POINTER,
            std::ptr::addr_of_mut!(file).cast(),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK || file.is_null() {
        return None;
    }
    // SAFETY: FILE_POINTER returns a live public `sqlite3_file` first.
    let methods = unsafe { (*file).pMethods };
    if methods.is_null() || !public_io_methods(methods) {
        return None;
    }
    Some((TrustedUnixConnection { vfs, methods }, file))
}

#[cfg(unix)]
/// # Errors
/// Returns an error unless the opened database uses bundled `SQLite` 3.49.1/default Unix VFS.
pub fn opened_database_identity(
    connection: &rusqlite::Connection,
) -> Result<DatabaseFileIdentity, IdentityError> {
    if !exact_sqlite() {
        return Err(IdentityError);
    }
    let (trusted, file) = trusted_unix_connection(connection).ok_or(IdentityError)?;
    #[cfg(test)]
    PRIVATE_PREFIX_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: the trusted witness validates the opened VFS and public file methods first.
    let unix = unsafe { &*file.cast::<UnixFilePrefix>() };
    if !exact_unix_file(unix, &trusted) {
        return Err(IdentityError);
    }
    identity_from_descriptor(unix.descriptor)
}

#[cfg(unix)]
fn identity_from_descriptor(
    descriptor: std::ffi::c_int,
) -> Result<DatabaseFileIdentity, IdentityError> {
    // SQLite owns this live descriptor for the duration of the borrowed
    // connection. Closing even a duplicate can release this process's POSIX
    // record locks on the inode, so inspect it without taking ownership.
    // SAFETY: FILE_POINTER supplied the descriptor from the live SQLite file;
    // the connection borrow keeps it open, and ManuallyDrop prevents close.
    let borrowed = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(descriptor) });
    let meta = borrowed.metadata().map_err(|_| IdentityError)?;
    if !meta.file_type().is_file() || meta.nlink() != 1 || meta.dev() == 0 || meta.ino() == 0 {
        return Err(IdentityError);
    }
    Ok(DatabaseFileIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    })
}

#[cfg(unix)]
pub(crate) fn exact_sqlite() -> bool {
    // SAFETY: SQLite returns its static source id for process lifetime.
    let source = unsafe { rusqlite::ffi::sqlite3_sourceid() };
    if source.is_null() {
        return false;
    }
    // SAFETY: checked non-null and SQLite owns the NUL-terminated source id.
    let source = unsafe { std::ffi::CStr::from_ptr(source) };
    (unsafe { rusqlite::ffi::sqlite3_libversion_number() }) == 3_049_001
        && source.to_bytes() == b"2025-02-18 13:38:58 873d4e274b4988d260ba8354a9718324a1c26187a4ab4c1cc0227c03d0f10e70"
}
#[cfg(unix)]
fn public_unix_vfs(
    connection: &rusqlite::Connection,
    trusted: *mut rusqlite::ffi::sqlite3_vfs,
) -> Option<*mut rusqlite::ffi::sqlite3_vfs> {
    let mut vfs = std::ptr::null_mut::<rusqlite::ffi::sqlite3_vfs>();
    // SAFETY: SQLite writes the main connection's public VFS pointer.
    let pointer_status = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_VFS_POINTER,
            std::ptr::addr_of_mut!(vfs).cast(),
        )
    };
    if pointer_status != rusqlite::ffi::SQLITE_OK || vfs.is_null() {
        return None;
    }
    (vfs == trusted && valid_public_unix_vfs(vfs)).then_some(vfs)
}
#[cfg(unix)]
pub(crate) fn valid_public_unix_vfs(vfs: *mut rusqlite::ffi::sqlite3_vfs) -> bool {
    if vfs.is_null() {
        return false;
    }
    let Ok(minimum_file_size) = i32::try_from(std::mem::size_of::<UnixFilePrefix>()) else {
        return false;
    };
    // SAFETY: VFS_POINTER returned a live public `sqlite3_vfs` for this connection.
    unsafe {
        let view = &*vfs;
        !view.zName.is_null()
            && std::ffi::CStr::from_ptr(view.zName).to_bytes() == b"unix"
            && view.iVersion >= 1
            && view.szOsFile >= minimum_file_size
            && view.xOpen.is_some()
            && view.xDelete.is_some()
            && view.xAccess.is_some()
            && view.xFullPathname.is_some()
    }
}
#[cfg(unix)]
fn public_io_methods(methods: *const rusqlite::ffi::sqlite3_io_methods) -> bool {
    // SAFETY: `sqlite3_file.pMethods` is public SQLite ABI data from FILE_POINTER.
    unsafe {
        (*methods).iVersion >= 1
            && (*methods).xClose.is_some()
            && (*methods).xRead.is_some()
            && (*methods).xWrite.is_some()
    }
}
#[cfg(unix)]
fn exact_unix_file(file: &UnixFilePrefix, trusted: &TrustedUnixConnection) -> bool {
    if file.vfs != trusted.vfs || file.methods != trusted.methods || file.descriptor < 0 {
        return false;
    }
    true
}

#[cfg(all(test, unix))]
static PRIVATE_PREFIX_ATTEMPTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
mod identity_tests;
