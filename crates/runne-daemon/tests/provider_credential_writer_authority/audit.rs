use std::fs::{self, File};
use std::io::Read as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

const RAW_TICKET_CANARY: [u8; 32] = [0xa7; 32];

pub(super) fn secret_canary(root: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut digest = Sha256::new();
    digest.update(b"runne-slice-e-secret-canary-v1\0");
    digest.update(root.as_os_str().as_bytes());
    format!("sk-slice-e-{}", hex::encode(digest.finalize())).into_bytes()
}

pub(super) fn sensitive_patterns(secret: &[u8]) -> Vec<Vec<u8>> {
    let secret_digest = Sha256::digest(secret);
    let ticket_digest = Sha256::digest(RAW_TICKET_CANARY);
    vec![
        secret.to_vec(),
        secret_digest.to_vec(),
        hex::encode(secret_digest).into_bytes(),
        RAW_TICKET_CANARY.to_vec(),
        ticket_digest.to_vec(),
        hex::encode(ticket_digest).into_bytes(),
    ]
}

pub(super) fn assert_live_children_clean(
    root: &Path,
    patterns: &[Vec<u8>],
) -> Result<(), &'static str> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,command="])
        .output()
        .map_err(|_| "process-list")?;
    if !output.status.success() {
        return Err("process-list-status");
    }
    let writer = root.join("Runne.app/Contents/MacOS/runne");
    let daemon = root.join("Runne.app/Contents/MacOS/runned");
    let mut writer_seen = false;
    let mut daemon_seen = false;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.trim_start().splitn(2, char::is_whitespace);
        let Some(pid) = fields.next().and_then(|value| value.parse::<i32>().ok()) else {
            continue;
        };
        let command = fields.next().unwrap_or("").trim_start();
        let executable = command.split_whitespace().next().map(Path::new);
        if executable != Some(writer.as_path()) && executable != Some(daemon.as_path()) {
            continue;
        }
        writer_seen |= executable == Some(writer.as_path());
        daemon_seen |= executable == Some(daemon.as_path());
        let bytes = process_arguments(pid)?;
        if patterns.iter().any(|pattern| contains(&bytes, pattern)) {
            return Err("sensitive-process-arguments");
        }
    }
    (writer_seen && daemon_seen)
        .then_some(())
        .ok_or("real-process-pair")
}

pub(super) fn assert_completion_receipt_safe(runtime: &Path) -> Result<(), &'static str> {
    let database = runtime.join("runne-daemon/event-log.db");
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| "receipt-open")?;
    let expected = [
        "operation_id",
        "installation_owner_id",
        "provider_id",
        "action",
        "target_credential_version",
        "target_ref_digest",
        "predecessor_lifecycle_revision",
        "predecessor_credential_fence",
        "claimed_ticket_attempt",
        "broker_migration_binding_digest",
        "qualified_release_tuple_digest",
        "readback_disposition",
        "readback_observation_digest",
        "readiness_observation_id",
        "successor_lifecycle_revision",
        "successor_credential_fence",
        "successor_readiness_revision",
        "active_credential_version",
        "active_ref_digest",
        "next_credential_version",
    ];
    let mut statement = connection
        .prepare("SELECT * FROM provider_credential_completion_receipts")
        .map_err(|_| "receipt-query")?;
    if statement.column_names().as_slice() != expected {
        return Err("receipt-columns");
    }
    let mut rows = statement.query([]).map_err(|_| "receipt-rows")?;
    let row = rows
        .next()
        .map_err(|_| "receipt-row")?
        .ok_or("receipt-missing")?;
    validate_receipt_row(row)?;
    rows.next()
        .map_err(|_| "receipt-row")?
        .is_none()
        .then_some(())
        .ok_or("receipt-cardinality")
}

fn validate_receipt_row(row: &rusqlite::Row<'_>) -> Result<(), &'static str> {
    use rusqlite::types::ValueRef;

    for index in 0..20 {
        let value = row.get_ref(index).map_err(|_| "receipt-value")?;
        let valid = match (index, value) {
            (0 | 13, ValueRef::Blob(value)) => value.len() == 16,
            (1 | 5 | 10 | 12 | 18, ValueRef::Blob(value)) => value.len() == 32,
            (2, ValueRef::Text(value)) => value == b"openai",
            (3, ValueRef::Text(value)) => value == b"PAIR",
            (11, ValueRef::Text(value)) => value == b"EXACT_VERSION",
            (9, ValueRef::Null) => true,
            (4 | 6..=8 | 14..=17 | 19, ValueRef::Integer(value)) => value > 0,
            _ => false,
        };
        if !valid {
            return Err("receipt-shape");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn process_arguments(pid: i32) -> Result<Vec<u8>, &'static str> {
    const MAX_BYTES: usize = 128 * 1024;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = 0_usize;
    // SAFETY: the read-only sysctl receives a fixed MIB and a valid size pointer.
    let sized = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if sized != 0 || size == 0 || size > MAX_BYTES {
        return Err("process-arguments-size");
    }
    let mut bytes = vec![0_u8; size];
    // SAFETY: `bytes` owns `size` writable bytes and sysctl cannot exceed it.
    let read = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 || size > bytes.len() {
        return Err("process-arguments-read");
    }
    bytes.truncate(size);
    Ok(bytes)
}

pub(super) fn tree_contains(root: &Path, patterns: &[&[u8]]) -> Result<bool, &'static str> {
    for entry in fs::read_dir(root).map_err(|_| "audit-directory")? {
        let entry = entry.map_err(|_| "audit-entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| "audit-metadata")?;
        if metadata.file_type().is_symlink() {
            return Err("audit-symlink");
        }
        if metadata.is_dir() {
            if tree_contains(&path, patterns)? {
                return Ok(true);
            }
        } else if metadata.is_file() && file_contains(&path, patterns)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn file_contains(path: &Path, patterns: &[&[u8]]) -> Result<bool, &'static str> {
    let longest = patterns
        .iter()
        .map(|pattern| pattern.len())
        .max()
        .unwrap_or(0);
    if longest == 0 {
        return Ok(false);
    }
    let mut file = File::open(path).map_err(|_| "audit-open")?;
    let mut carry = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut chunk).map_err(|_| "audit-read")?;
        if read == 0 {
            return Ok(false);
        }
        carry.extend_from_slice(&chunk[..read]);
        if patterns.iter().any(|pattern| contains(&carry, pattern)) {
            return Ok(true);
        }
        let retain = longest.saturating_sub(1).min(carry.len());
        carry.drain(..carry.len() - retain);
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
