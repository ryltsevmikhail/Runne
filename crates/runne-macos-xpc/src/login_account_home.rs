use std::path::PathBuf;

use crate::QualificationRunnerXpcError;

/// Returns the canonical home directory of the current non-root login account.
///
/// # Errors
///
/// Rejects an unavailable account, a non-canonical directory, or changed UID
/// or login-session binding. Returns [`QualificationRunnerXpcError::Unsupported`]
/// outside macOS.
#[cfg(target_os = "macos")]
pub fn current_login_account_home() -> Result<PathBuf, QualificationRunnerXpcError> {
    let euid = effective_uid();
    let binding = crate::current_login_session_binding()?;
    if euid == 0 || binding.expected_euid() != euid {
        return Err(QualificationRunnerXpcError::Rejected);
    }
    let home = account_home(euid)?;
    let after_euid = effective_uid();
    let after_binding = crate::current_login_session_binding()?;
    (after_euid == euid && after_binding == binding && after_binding.expected_euid() == after_euid)
        .then_some(home)
        .ok_or(QualificationRunnerXpcError::Rejected)
}

#[cfg(not(target_os = "macos"))]
/// Returns an unsupported error because account-home lookup is macOS-only.
///
/// # Errors
///
/// Always returns [`QualificationRunnerXpcError::Unsupported`].
pub const fn current_login_account_home() -> Result<PathBuf, QualificationRunnerXpcError> {
    Err(QualificationRunnerXpcError::Unsupported)
}

#[cfg(target_os = "macos")]
fn account_home(euid: u32) -> Result<PathBuf, QualificationRunnerXpcError> {
    use std::ffi::{CStr, OsStr};
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt as _;

    const PASSWD_BUFFER_BYTES: usize = 64 * 1024;

    let mut record = MaybeUninit::<libc::passwd>::zeroed();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; PASSWD_BUFFER_BYTES];
    // SAFETY: all pointers are valid for the supplied fixed buffer; `result`
    // is checked against `record` before reading any populated fields.
    let status = unsafe {
        libc::getpwuid_r(
            euid,
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            std::ptr::addr_of_mut!(result),
        )
    };
    if status != 0 || result != record.as_mut_ptr() {
        return Err(QualificationRunnerXpcError::Rejected);
    }
    // SAFETY: a successful `getpwuid_r` that returned `record` initialized it.
    let record = unsafe { record.assume_init() };
    if record.pw_uid != euid || record.pw_dir.is_null() {
        return Err(QualificationRunnerXpcError::Rejected);
    }
    // SAFETY: `getpwuid_r` returns a NUL-terminated directory string while
    // `buffer` remains live.
    let directory = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
    if directory.is_empty() {
        return Err(QualificationRunnerXpcError::Rejected);
    }
    let raw = PathBuf::from(OsStr::from_bytes(directory));
    if !raw.is_absolute() {
        return Err(QualificationRunnerXpcError::Rejected);
    }
    let canonical =
        std::fs::canonicalize(&raw).map_err(|_| QualificationRunnerXpcError::Rejected)?;
    (canonical == raw)
        .then_some(raw)
        .ok_or(QualificationRunnerXpcError::Rejected)
}

#[cfg(target_os = "macos")]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and reads current process state.
    unsafe { libc::geteuid() }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::process::Command;

    use super::current_login_account_home;

    const CHILD: &str = "RUNNE_XPC_LOGIN_HOME_OVERRIDE_CHILD";
    const OVERRIDE: &str = "/private/tmp/runne-login-home-override-never-use";

    #[test]
    fn account_home_ignores_a_subprocess_home_override() {
        if std::env::var_os(CHILD).is_some() {
            let home = current_login_account_home().expect("current login account home");
            assert!(home.is_absolute());
            assert_eq!(std::fs::canonicalize(&home).expect("canonical home"), home);
            assert_ne!(home, std::path::Path::new(OVERRIDE));
            return;
        }
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "login_account_home::tests::account_home_ignores_a_subprocess_home_override",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("HOME", OVERRIDE)
            .status()
            .expect("subprocess");
        assert!(status.success());
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::current_login_account_home;

    #[test]
    fn account_home_is_unsupported_off_macos() {
        assert!(matches!(
            current_login_account_home(),
            Err(crate::QualificationRunnerXpcError::Unsupported)
        ));
    }
}
