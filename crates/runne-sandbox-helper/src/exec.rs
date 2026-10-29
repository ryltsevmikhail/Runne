//! Replace the helper with the requested program.

use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

/// Executes `program` with `args`; returns a diagnostic only when `execv`
/// fails, because a successful call never returns.
pub fn replace(program: &OsStr, args: &[OsString]) -> String {
    let Ok(program) = CString::new(program.as_bytes()) else {
        return "program contains a NUL byte".to_string();
    };
    let mut exec_arguments = Vec::with_capacity(args.len() + 1);
    exec_arguments.push(program.clone());
    for argument in args {
        let Ok(argument) = CString::new(argument.as_bytes()) else {
            return "argument contains a NUL byte".to_string();
        };
        exec_arguments.push(argument);
    }

    let mut pointers: Vec<*const libc::c_char> =
        exec_arguments.iter().map(|value| value.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // SAFETY: both the program and the NUL-terminated argument vector remain
    // alive for the duration of the call.
    unsafe { libc::execv(program.as_ptr(), pointers.as_ptr()) };
    format!(
        "cannot execute {}: {}",
        program.to_string_lossy(),
        std::io::Error::last_os_error()
    )
}
