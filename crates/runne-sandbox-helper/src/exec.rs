//! Replace the helper with the requested program.

use std::ffi::{CString, OsStr, OsString};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;

/// Executes `program` with `args`; returns a diagnostic only when `execv`
/// fails, because a successful call never returns.
///
/// `keep` names the status descriptor: it stays open across a failed `execv`
/// so the helper can still report that failure, while its close-on-exec flag
/// removes it when the call succeeds.
pub fn replace(program: &OsStr, args: &[OsString], keep: Option<RawFd>) -> String {
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
    close_inherited_descriptors(keep);
    // SAFETY: both the program and the NUL-terminated argument vector remain
    // alive for the duration of the call.
    unsafe { libc::execv(program.as_ptr(), pointers.as_ptr()) };
    format!(
        "cannot execute {}: {}",
        program.to_string_lossy(),
        std::io::Error::last_os_error()
    )
}

/// Closes every descriptor above stdio except the status descriptor before the
/// target program starts.
///
/// The helper has already consumed the profile and working-directory
/// descriptors, so nothing above stderr is needed. Closing the rest keeps a
/// descriptor the runtime forgot to mark close-on-exec out of the program; the
/// status descriptor is kept only until `execv` closes it through its own flag.
fn close_inherited_descriptors(keep: Option<RawFd>) {
    // SAFETY: getdtablesize only reads this process's descriptor limit.
    let limit = unsafe { libc::getdtablesize() };
    for fd in 3..limit {
        if keep == Some(fd) {
            continue;
        }
        // SAFETY: closing a descriptor this process owns is valid; EBADF for a
        // descriptor that was never open is expected and ignored.
        unsafe { libc::close(fd) };
    }
}
