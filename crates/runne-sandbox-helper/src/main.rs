//! Per-invocation macOS sandbox helper.
//!
//! This binary is spawned by the runtime, applies a Seatbelt sandbox profile to
//! itself, and then executes the requested tool. The helper must be signed with
//! the `com.apple.security.app-sandbox` entitlement (ad-hoc for the spike,
//! Developer ID for production).

#![allow(unsafe_code)]

use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    run_macos_main()
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    // The helper is macOS-only. On other platforms we compile a stub so the
    // workspace builds on Linux/Windows CI, but the binary is a no-op.
    eprintln!("runne-sandbox-helper: macOS-only binary");
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
fn run_macos_main() -> ExitCode {
    use std::env;

    /// Exit codes used by the helper to report results to the parent.
    #[derive(Clone, Copy, Debug)]
    #[repr(u8)]
    #[allow(dead_code)]
    enum HelperExit {
        /// Sandbox applied and target file access was denied as expected.
        DenyWorked = 0,
        /// Missing arguments or invalid usage.
        BadUsage = 1,
        /// `sandbox_init` failed.
        SandboxInitFailed = 2,
        /// The sandbox did not deny access to `/etc/passwd`.
        DenyFailed = 3,
    }

    // For the spike we do not exec a real tool. Instead we verify that the
    // sandbox denies read access to `/etc/passwd`.
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "--self-test" {
        return run_self_test();
    }

    if args.len() < 2 {
        eprintln!("usage: runne-sandbox-helper [--self-test] | <tool> [args...]");
        return ExitCode::from(HelperExit::BadUsage as u8);
    }

    // Production path would apply a profile and then execve the tool. The spike
    // only implements the self-test path above.
    eprintln!("runne-sandbox-helper: only --self-test is implemented in the spike");
    ExitCode::from(HelperExit::BadUsage as u8)
}

#[cfg(target_os = "macos")]
fn run_self_test() -> ExitCode {
    use std::ffi::{CStr, CString};

    unsafe extern "C" {
        /// Applies a Seatbelt profile to the current process.
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            errorbuf: *mut *mut libc::c_char,
        ) -> libc::c_int;
    }

    /// Exit codes used by the helper to report results to the parent.
    #[derive(Clone, Copy, Debug)]
    #[repr(u8)]
    #[allow(dead_code)]
    enum HelperExit {
        /// Sandbox applied and target file access was denied as expected.
        DenyWorked = 0,
        /// `sandbox_init` failed.
        SandboxInitFailed = 2,
        /// The sandbox did not deny access to `/etc/passwd`.
        DenyFailed = 3,
    }

    // Minimal profile that denies read access to `/etc/passwd`. This proves the
    // sandbox is active after explicit sandbox_init.
    let profile = CString::new("(version 1)\n(debug deny)\n(deny file-read*)\n")
        .expect("profile contains no interior nul bytes");

    let mut errmsg: *mut libc::c_char = std::ptr::null_mut();
    let ret = unsafe { sandbox_init(profile.as_ptr(), 0, std::ptr::addr_of_mut!(errmsg)) };
    if ret != 0 {
        if !errmsg.is_null() {
            let c_str = unsafe { CStr::from_ptr(errmsg) };
            eprintln!("sandbox_init failed: {}", c_str.to_string_lossy());
        }
        return ExitCode::from(HelperExit::SandboxInitFailed as u8);
    }

    match std::fs::read_to_string("/etc/passwd") {
        Ok(_) => {
            eprintln!("sandbox self-test failed: /etc/passwd was readable");
            ExitCode::from(HelperExit::DenyFailed as u8)
        }
        Err(_) => {
            // Denied as expected.
            ExitCode::from(HelperExit::DenyWorked as u8)
        }
    }
}
