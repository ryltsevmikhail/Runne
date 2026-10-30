#![allow(unsafe_code)]

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;

mod coding;
pub(crate) mod coding_arguments;
#[cfg(not(target_os = "macos"))]
mod coding_command;
#[cfg(target_os = "macos")]
mod coding_command_sandbox;
pub(crate) mod coding_fs;
mod coding_listing;
mod coding_process;
#[cfg(all(test, target_os = "linux"))]
mod coding_tests;
#[cfg(feature = "test-support")]
pub(crate) mod credential_companion_test_support;
mod output;
mod protocol;
mod request;
#[cfg(all(
    feature = "test-support",
    feature = "desktop-protected",
    target_os = "linux"
))]
#[path = "safe_tool_helper/target_race_fixture.rs"]
mod target_race_fixture;
#[cfg(all(feature = "desktop-protected", unix))]
pub(crate) use request::encode_request;
pub use request::{HelperProcessError, run};
mod validate;
mod verification;
#[cfg(all(feature = "desktop-protected", unix))]
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
        RequestV1::Coding {
            binding,
            tool_name,
            arguments,
            root: expected_root,
            expected,
        } => coding::execute(
            root,
            binding,
            &tool_name,
            &arguments,
            expected_root,
            expected,
        ),
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
                openat(root, &path, O_PATH | libc::O_NOFOLLOW).map_err(|_| "read_denied")?;
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
            let named = openat(root, &path, O_PATH | libc::O_NOFOLLOW)
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
            #[cfg(all(
                feature = "test-support",
                feature = "desktop-protected",
                target_os = "linux"
            ))]
            target_race_fixture::after_create_before_write(root)
                .map_err(|_| effect_error("target_race_fixture"))?;
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
            let named = openat(root, &path, O_PATH | libc::O_NOFOLLOW)
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

use unix_io::*;
mod platform;
mod unix_io;
use platform::O_PATH;

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

#[cfg(all(test, target_os = "linux"))]
#[path = "safe_tool_helper/tests.rs"]
mod tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "safe_tool_helper/tests_macos.rs"]
mod tests_macos;
