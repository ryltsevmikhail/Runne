// Open provider-credential item access.
//
// macOS 27 erases the partition ACL on save, so exact cross-process ACLs are
// unusable there. The item is created through the system `security` tool with
// `-A`; the provider-credential payload carries its own binding and is
// verified by the reader. Consequence: any process of the user can read the
// item without a prompt; this is the conscious macOS 27 trade-off held as P1
// until a signed bundle can enforce a stable identity.

/// Writes one open generic-password item through the system `security` tool.
///
/// The tool runs in a new session so its password prompt reads the pipe rather
/// than the caller's controlling terminal. The value never enters argv.
///
/// # Errors
///
/// Returns a closed error when the item cannot be created or read back.
pub fn write_open_generic_password(
    service: &str,
    account: &str,
    value: &str,
) -> Result<(), KeychainAclError> {
    use std::io::Write as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    let mut delete = Command::new("/usr/bin/security");
    delete
        .args(["delete-generic-password", "-s", service, "-a", account])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid only detaches the child from the terminal.
    unsafe { delete.pre_exec(detach_terminal) };
    let _ = delete.status();
    let mut add = Command::new("/usr/bin/security");
    add.args([
        "add-generic-password",
        "-A",
        "-U",
        "-s",
        service,
        "-a",
        account,
        "-w",
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    // SAFETY: setsid only detaches the child from the terminal.
    unsafe { add.pre_exec(detach_terminal) };
    let mut child = add.spawn().map_err(|_| KeychainAclError::OperationFailed)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or(KeychainAclError::OperationFailed)?;
    stdin
        .write_all(value.as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .and_then(|()| stdin.write_all(value.as_bytes()))
        .and_then(|()| stdin.write_all(b"\n"))
        .map_err(|_| KeychainAclError::OperationFailed)?;
    drop(stdin);
    let _ = child.wait();
    match read_open_generic_password(service, account)? {
        Some(stored) if stored == value.as_bytes() => Ok(()),
        _ => Err(KeychainAclError::OperationFailed),
    }
}

/// Deletes one open generic-password item by query.
///
/// # Errors
///
/// Returns a closed error when the item cannot be deleted.
pub fn delete_open_generic_password(
    service: &str,
    account: &str,
) -> Result<(), KeychainAclError> {
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    let mut delete = Command::new("/usr/bin/security");
    delete
        .args(["delete-generic-password", "-s", service, "-a", account])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid only detaches the child from the terminal.
    unsafe { delete.pre_exec(detach_terminal) };
    match delete.status() {
        Ok(status) if status.success() => Ok(()),
        _ => Err(KeychainAclError::OperationFailed),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn detach_terminal() -> std::io::Result<()> {
    // SAFETY: setsid has no memory preconditions and only affects the child.
    unsafe { libc::setsid() };
    Ok(())
}

/// Reads one open generic-password item through the system `security` tool.
///
/// The tool is the stable read-only bridge for items created with `-A`; the
/// legacy `SecKeychain` search path rejects those items with `errSecAuthFailed`
/// on macOS 27 even when the ACL lists no application.
///
/// # Errors
///
/// Returns a closed error when the item exists but cannot be read.
pub fn read_open_generic_password(
    service: &str,
    account: &str,
) -> Result<Option<Vec<u8>>, KeychainAclError> {
    use std::process::{Command, Stdio};
    let output = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| KeychainAclError::OperationFailed)?;
    if !output.status.success() {
        // 44 is errSecItemNotFound from the CLI.
        return if output.status.code() == Some(44) {
            Ok(None)
        } else {
            Err(KeychainAclError::AccessDenied)
        };
    }
    let mut value = output.stdout;
    if value.last() == Some(&b'\n') {
        value.pop();
    }
    if value.is_empty() {
        return Err(KeychainAclError::OperationFailed);
    }
    Ok(Some(value))
}
