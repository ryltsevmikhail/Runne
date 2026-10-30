//! Minimal binding to the macOS Seatbelt profile API.

use std::ffi::{CStr, CString};

unsafe extern "C" {
    /// Applies a Seatbelt profile to the current process.
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;
    /// Releases an error string returned by `sandbox_init`.
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Applies one Seatbelt profile to the current process.
///
/// # Errors
/// Returns the kernel diagnostic when the profile is rejected or the process
/// is already confined by a profile this one cannot narrow.
pub fn apply(profile: &CString) -> Result<(), String> {
    let mut error = std::ptr::null_mut();
    // SAFETY: the profile is a valid NUL-terminated string and the error
    // pointer is a valid out-parameter owned by this stack frame.
    let result = unsafe { sandbox_init(profile.as_ptr(), 0, std::ptr::addr_of_mut!(error)) };
    if result == 0 {
        return Ok(());
    }
    if error.is_null() {
        return Err("sandbox_init failed without a diagnostic".to_string());
    }
    // SAFETY: sandbox_init returned non-zero, so error points at an allocated
    // NUL-terminated diagnostic that sandbox_free_error releases.
    let message = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: the same allocation is released exactly once here.
    unsafe { sandbox_free_error(error) };
    Err(message)
}
