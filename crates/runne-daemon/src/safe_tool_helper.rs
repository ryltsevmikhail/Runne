#![allow(unsafe_code)]

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;

mod output;
mod protocol;
mod request;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(crate) use request::encode_request;
pub use request::{HelperProcessError, run};
mod validate;
mod verification;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(crate) use output::OutputError;
pub(crate) use output::parse_output;
use protocol::ErrorV1;
pub(crate) use protocol::{BindingV1, IdentityV1, ReceiptV1, RequestV1, VersionV1};
use validate::{valid_path, validate_binding};
pub(crate) use verification::verify_bound_receipt;

const MAX_INPUT: usize = 16 * 1024;
const MAX_CONTENT: usize = 8 * 1024;

fn execute(root: &File, input: &[u8]) -> Result<ReceiptV1, &'static str> {
    if input.len() > MAX_INPUT {
        return Err("input_bound");
    }
    let request: RequestV1 = serde_json::from_slice(input).map_err(|_| "invalid_request")?;
    let root_identity = identity(root)?;
    match request {
        RequestV1::Read {
            binding,
            path,
            root: expected_root,
            expected,
        } => {
            validate_binding(&binding)?;
            let path = valid_path(path)?;
            if root_identity != expected_root {
                return Err("root_changed");
            }
            let pinned =
                openat(root, &path, libc::O_PATH | libc::O_NOFOLLOW).map_err(|_| "read_denied")?;
            let before = version(&pinned)?;
            if before != expected || before.size as usize > MAX_CONTENT || !regular_single(&pinned)?
            {
                return Err("target_changed");
            }
            // Only reopen after fstat proved the pinned object is a regular,
            // single-link file. /proc/self/fd follows our held O_PATH inode,
            // not a raced replacement at the workspace name.
            let file = reopen_pinned_read(&pinned)?;
            if version(&file).map_err(effect_error)? != before
                || !regular_single(&file).map_err(effect_error)?
            {
                return Err("effect_started_target_changed");
            }
            let bytes = read_bounded(&file, before.size as usize).map_err(effect_error)?;
            if version(&file).map_err(effect_error)? != before
                || version(&pinned).map_err(effect_error)? != before
                || identity(root).map_err(effect_error)? != root_identity
            {
                return Err("effect_started_target_changed");
            }
            let named = openat(root, &path, libc::O_PATH | libc::O_NOFOLLOW)
                .map_err(|_| "effect_started_target_changed")?;
            if version(&named).map_err(effect_error)? != before
                || !regular_single(&named).map_err(effect_error)?
            {
                return Err("effect_started_target_changed");
            }
            receipt("read", binding, path, root_identity, before, bytes).map_err(effect_error)
        }
        RequestV1::CreateNew {
            binding,
            path,
            root: expected_root,
            expected_absent,
            content_base64,
        } => {
            validate_binding(&binding)?;
            let path = valid_path(path)?;
            let bytes = STANDARD
                .decode(content_base64.as_bytes())
                .map_err(|_| "invalid_content")?;
            if bytes.len() > MAX_CONTENT {
                return Err("content_bound");
            }
            if root_identity != expected_root {
                return Err("root_changed");
            }
            if !expected_absent {
                return Err("absence_precondition_required");
            }
            let file = openat(
                root,
                &path,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
            .map_err(|_| "target_exists_or_denied")?;
            write_all(&file, &bytes).map_err(effect_error)?;
            if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
                return Err("effect_started_sync_failed");
            }
            let target = version(&file).map_err(effect_error)?;
            if !regular_single(&file).map_err(effect_error)? || target.size as usize != bytes.len()
            {
                return Err("effect_started_target_invalid");
            }
            let actual = read_bounded(&file, bytes.len()).map_err(effect_error)?;
            if actual != bytes || identity(root).map_err(effect_error)? != root_identity {
                return Err("effect_started_target_changed");
            }
            let named = openat(root, &path, libc::O_PATH | libc::O_NOFOLLOW)
                .map_err(|_| "effect_started_target_changed")?;
            if version(&named).map_err(effect_error)? != target
                || !regular_single(&named).map_err(effect_error)?
                || version(&file).map_err(effect_error)? != target
            {
                return Err("effect_started_target_changed");
            }
            if unsafe { libc::fsync(root.as_raw_fd()) } != 0 {
                return Err("effect_started_sync_failed");
            }
            receipt("create_new", binding, path, root_identity, target, actual)
        }
    }
}

fn openat(root: &File, path: &CString, flags: i32) -> Result<File, ()> {
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            path.as_ptr(),
            flags | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn reopen_pinned_read(pinned: &File) -> Result<File, &'static str> {
    let proc_path =
        CString::new(format!("/proc/self/fd/{}", pinned.as_raw_fd())).map_err(|_| "read_denied")?;
    let fd = unsafe {
        libc::open(
            proc_path.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("read_denied");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn identity(file: &File) -> Result<IdentityV1, &'static str> {
    let stat = stat(file)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err("root_invalid");
    }
    Ok(IdentityV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn version(file: &File) -> Result<VersionV1, &'static str> {
    let stat = stat(file)?;
    Ok(VersionV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: u64::try_from(stat.st_size).map_err(|_| "target_invalid")?,
        mtime_sec: stat.st_mtime,
        mtime_nsec: stat.st_mtime_nsec,
        ctime_sec: stat.st_ctime,
        ctime_nsec: stat.st_ctime_nsec,
    })
}

fn stat(file: &File) -> Result<libc::stat, &'static str> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err("stat_failed");
    }
    Ok(stat)
}

fn regular_single(file: &File) -> Result<bool, &'static str> {
    let stat = stat(file)?;
    Ok(stat.st_mode & libc::S_IFMT == libc::S_IFREG && stat.st_nlink == 1)
}

fn read_bounded(file: &File, length: usize) -> Result<Vec<u8>, &'static str> {
    if length > MAX_CONTENT {
        return Err("content_bound");
    }
    let mut bytes = vec![0; length];
    let read = unsafe { libc::pread(file.as_raw_fd(), bytes.as_mut_ptr().cast(), length, 0) };
    if read < 0 || read as usize != length {
        return Err("read_failed");
    }
    Ok(bytes)
}

fn write_all(file: &File, bytes: &[u8]) -> Result<(), &'static str> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = unsafe {
            libc::write(
                file.as_raw_fd(),
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count <= 0 {
            return Err("write_failed");
        }
        offset += count as usize;
    }
    Ok(())
}

fn receipt(
    operation: &'static str,
    binding: BindingV1,
    path: CString,
    root: IdentityV1,
    target: VersionV1,
    bytes: Vec<u8>,
) -> Result<ReceiptV1, &'static str> {
    if bytes.len() > MAX_CONTENT {
        return Err("content_bound");
    }
    Ok(ReceiptV1 {
        status: "success".to_owned(),
        version: 1,
        operation: operation.to_owned(),
        path: path.into_string().map_err(|_| "path_denied")?,
        binding,
        root,
        target,
        byte_length: bytes.len(),
        truncated: false,
        sha256: hex::encode(Sha256::digest(&bytes)),
        bytes_base64: STANDARD.encode(bytes),
    })
}

fn effect_error(_: &'static str) -> &'static str {
    "effect_started_operation_uncertain"
}

use std::os::fd::FromRawFd;

#[cfg(test)]
#[path = "safe_tool_helper/tests.rs"]
mod tests;
