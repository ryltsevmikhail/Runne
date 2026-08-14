//! Constructor-time capture of the bundled Unix VFS before application code runs.

use std::sync::atomic::{AtomicPtr, Ordering};

use rusqlite::ffi::{self, sqlite3_vfs};

static TRUSTED_BUILTIN_VFS: AtomicPtr<sqlite3_vfs> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn capture_trusted_builtin_vfs() {
    // SAFETY: SQLite initialization and default-VFS lookup are process-global SQLite APIs.
    let initialized = unsafe { ffi::sqlite3_initialize() } == ffi::SQLITE_OK;
    // SAFETY: default/named VFS pointers have process lifetime after initialization.
    let builtin = unsafe { ffi::sqlite3_vfs_find(std::ptr::null()) };
    let named_unix = unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
    if initialized
        && super::exact_sqlite()
        && builtin == named_unix
        && super::valid_public_unix_vfs(builtin)
    {
        let _ = TRUSTED_BUILTIN_VFS.compare_exchange(
            std::ptr::null_mut(),
            builtin,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static CAPTURE_TRUSTED_BUILTIN_VFS: extern "C" fn() = capture_trusted_builtin_vfs;

#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static CAPTURE_TRUSTED_BUILTIN_VFS: extern "C" fn() = capture_trusted_builtin_vfs;

#[allow(clippy::redundant_pub_crate)]
pub(super) fn trusted_builtin_vfs() -> Option<*mut sqlite3_vfs> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let builtin = TRUSTED_BUILTIN_VFS.load(Ordering::Acquire);
        (!builtin.is_null()).then_some(builtin)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}
