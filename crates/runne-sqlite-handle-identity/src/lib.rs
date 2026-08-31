//! Narrow safe boundary for SQLite's actual main-file movement check.

#![deny(unsafe_op_in_unsafe_fn)]

/// Fieldless failure for an unsupported or rejected SQLite file control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleIdentityError;

fn movement_result(result: i32, moved: i32) -> Result<bool, HandleIdentityError> {
    if result == rusqlite::ffi::SQLITE_OK {
        Ok(moved != 0)
    } else {
        Err(HandleIdentityError)
    }
}

/// Returns whether SQLite's open main-file handle no longer names its path.
///
/// An unsupported VFS or any file-control error is returned fail-closed.
pub fn main_file_has_moved(connection: &rusqlite::Connection) -> Result<bool, HandleIdentityError> {
    let mut moved = 1_i32;
    // SAFETY: SQLite owns the live handle, "main" is NUL-terminated, and the
    // documented opcode writes one i32 during this synchronous call only.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
            std::ptr::from_mut(&mut moved).cast(),
        )
    };
    movement_result(result, moved)
}

/// Returns movement state for SQLite's open rollback-journal or WAL handle.
///
/// `Ok(None)` means that SQLite has no open journal handle. Unsupported
/// controls, missing methods, and non-OK return codes fail closed.
pub fn journal_file_has_moved(
    connection: &rusqlite::Connection,
) -> Result<Option<bool>, HandleIdentityError> {
    let mut journal = std::ptr::null_mut::<rusqlite::ffi::sqlite3_file>();
    // SAFETY: SQLite writes one borrowed pointer during the call. We inspect it
    // synchronously while the connection remains borrowed and invoke only its
    // documented xFileControl method with an i32 output parameter.
    unsafe {
        let result = rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_JOURNAL_POINTER,
            std::ptr::from_mut(&mut journal).cast(),
        );
        if result != rusqlite::ffi::SQLITE_OK {
            return Err(HandleIdentityError);
        }
        let Some(file) = journal.as_ref() else {
            return Ok(None);
        };
        let Some(methods) = file.pMethods.as_ref() else {
            return Ok(None);
        };
        let control = methods.xFileControl.ok_or(HandleIdentityError)?;
        let mut moved = 1_i32;
        let result = control(
            journal,
            rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
            std::ptr::from_mut(&mut moved).cast(),
        );
        movement_result(result, moved).map(Some)
    }
}

fn persistent_wal_control(
    connection: &rusqlite::Connection,
    mut value: i32,
) -> Result<i32, HandleIdentityError> {
    // SAFETY: SQLite reads and writes one live i32 during this synchronous call.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            std::ptr::from_mut(&mut value).cast(),
        )
    };
    (result == rusqlite::ffi::SQLITE_OK)
        .then_some(value)
        .ok_or(HandleIdentityError)
}

/// Keeps one stable WAL/SHM file set for a caller-owned inspection window.
pub fn configure_persistent_wal(
    connection: &rusqlite::Connection,
) -> Result<(), HandleIdentityError> {
    persistent_wal_control(connection, 1)
        .and_then(|value| (value == 1).then_some(()).ok_or(HandleIdentityError))
}

/// Reads back the main file's persistent-WAL setting.
pub fn persistent_wal_enabled(
    connection: &rusqlite::Connection,
) -> Result<bool, HandleIdentityError> {
    persistent_wal_control(connection, -1).map(|value| value == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_sqlite_ok_is_accepted() {
        assert_eq!(movement_result(rusqlite::ffi::SQLITE_OK, 0), Ok(false));
        assert_eq!(movement_result(rusqlite::ffi::SQLITE_OK, 1), Ok(true));
        assert_eq!(
            movement_result(rusqlite::ffi::SQLITE_NOTFOUND, 0),
            Err(HandleIdentityError)
        );
        assert_eq!(
            movement_result(rusqlite::ffi::SQLITE_ERROR, 0),
            Err(HandleIdentityError)
        );
    }
}
