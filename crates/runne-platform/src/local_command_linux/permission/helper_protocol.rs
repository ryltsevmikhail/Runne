use super::super::LinuxCommandError;
use super::helper::{
    PermissionHelperBindingObservationV1, PermissionHelperObservationV1,
    PermissionHelperOperationV1, PermissionHelperTargetVersionV1,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    time::{SystemTime, UNIX_EPOCH},
};

const HELPER_MAX_INPUT: usize = 16 * 1024;
const HELPER_MAX_CONTENT: usize = 8 * 1024;
const HELPER_REQUEST_DOMAIN: &[u8] = b"runne:d21:tool-helper-request:v1\0";

#[derive(Clone)]
pub(super) struct ParsedHelperRequest {
    pub(super) observation: PermissionHelperObservationV1,
    path: CString,
    absent: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperBindingV1 {
    taskrun_id: String,
    attempt_id: String,
    cycle_id: String,
    proposal_index: u32,
    taskrun_version: u64,
    assignment_fence: u64,
    invocation_digest: String,
    environment_digest: String,
    approval_digest: String,
    expires_at_unix_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperIdentityV1 {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperVersionV1 {
    device: u64,
    inode: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum HelperRequestV1 {
    Read {
        binding: HelperBindingV1,
        path: String,
        root: HelperIdentityV1,
        expected: HelperVersionV1,
    },
    CreateNew {
        binding: HelperBindingV1,
        path: String,
        root: HelperIdentityV1,
        expected_absent: bool,
        content_base64: String,
    },
}

pub(super) fn parse_helper_request(bytes: &[u8]) -> Result<ParsedHelperRequest, LinuxCommandError> {
    if bytes.is_empty() || bytes.len() > HELPER_MAX_INPUT {
        return Err(LinuxCommandError::Invalid);
    }
    let (binding, path, root, operation, target, content, original_base64) =
        match serde_json::from_slice(bytes).map_err(|_| LinuxCommandError::Invalid)? {
            HelperRequestV1::Read {
                binding,
                path,
                root,
                expected,
            } => (
                binding,
                path,
                root,
                PermissionHelperOperationV1::Read,
                Some(expected),
                Vec::new(),
                None,
            ),
            HelperRequestV1::CreateNew {
                binding,
                path,
                root,
                expected_absent,
                content_base64,
            } => {
                if !expected_absent || content_base64.len() > 11_000 {
                    return Err(LinuxCommandError::Invalid);
                }
                let content = STANDARD
                    .decode(content_base64.as_bytes())
                    .map_err(|_| LinuxCommandError::Invalid)?;
                if content.len() > HELPER_MAX_CONTENT {
                    return Err(LinuxCommandError::Invalid);
                }
                (
                    binding,
                    path,
                    root,
                    PermissionHelperOperationV1::CreateNew,
                    None,
                    content,
                    Some(content_base64),
                )
            }
        };
    let bounded = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    };
    if !bounded(&binding.taskrun_id)
        || !bounded(&binding.attempt_id)
        || !bounded(&binding.cycle_id)
        || !bounded(&binding.invocation_digest)
        || !bounded(&binding.environment_digest)
        || !bounded(&binding.approval_digest)
        || binding.taskrun_version == 0
        || binding.assignment_fence == 0
        || !helper_is_current(binding.expires_at_unix_ms)?
    {
        return Err(LinuxCommandError::Invalid);
    }
    let arguments_digest = helper_arguments_digest(&path, original_base64.as_deref())?;
    let expires_at_unix_ms = binding.expires_at_unix_ms;
    let binding = PermissionHelperBindingObservationV1 {
        taskrun_id: binding.taskrun_id,
        attempt_id: binding.attempt_id,
        cycle_id: binding.cycle_id,
        proposal_index: binding.proposal_index,
        taskrun_version: binding.taskrun_version,
        assignment_fence: binding.assignment_fence,
        invocation_digest: binding.invocation_digest,
        environment_digest: binding.environment_digest,
        approval_digest: binding.approval_digest,
        expires_at_unix_ms,
    };
    let path_c = helper_target_path(&path)?;
    if target.is_some_and(|version| version.size > HELPER_MAX_CONTENT as u64) {
        return Err(LinuxCommandError::Invalid);
    }
    let target = target.map(|version| PermissionHelperTargetVersionV1 {
        device: version.device,
        inode: version.inode,
        size: version.size,
        mtime_sec: version.mtime_sec,
        mtime_nsec: version.mtime_nsec,
        ctime_sec: version.ctime_sec,
        ctime_nsec: version.ctime_nsec,
    });
    Ok(ParsedHelperRequest {
        observation: PermissionHelperObservationV1 {
            operation,
            path,
            request_digest: helper_request_digest(bytes),
            arguments_digest,
            binding,
            content_length: content.len(),
            content_digest: Sha256::digest(&content).into(),
            root_device: root.device,
            root_inode: root.inode,
            target,
            expires_at_unix_ms,
        },
        path: path_c,
        absent: operation == PermissionHelperOperationV1::CreateNew,
    })
}

pub(super) fn helper_is_current(expiry: u64) -> Result<bool, LinuxCommandError> {
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LinuxCommandError::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| LinuxCommandError::Invalid)?;
    Ok(expiry > now)
}

pub(super) fn helper_request_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(HELPER_REQUEST_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn helper_arguments_digest(
    path: &str,
    original_base64: Option<&str>,
) -> Result<[u8; 32], LinuxCommandError> {
    let value = match original_base64 {
        Some(content_base64) => serde_json::json!({"path": path, "content_base64": content_base64}),
        None => serde_json::json!({"path": path}),
    };
    Ok(Sha256::digest(serde_json::to_vec(&value).map_err(|_| LinuxCommandError::Invalid)?).into())
}

fn helper_target_path(path: &str) -> Result<CString, LinuxCommandError> {
    if path.is_empty()
        || path.len() > 255
        || path == "."
        || path == ".."
        || path.contains('/')
        || path.contains('\\')
        || path.as_bytes().contains(&0)
    {
        return Err(LinuxCommandError::Invalid);
    }
    CString::new(path).map_err(|_| LinuxCommandError::Invalid)
}

pub(super) fn check_helper_target(
    parsed: &ParsedHelperRequest,
    workspace: &File,
) -> Result<(), LinuxCommandError> {
    let mut root = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(workspace.as_raw_fd(), &mut root) } != 0
        || root.st_mode & libc::S_IFMT != libc::S_IFDIR
        || root.st_dev as u64 != parsed.observation.root_device
        || root.st_ino as u64 != parsed.observation.root_inode
    {
        return Err(LinuxCommandError::Unverified);
    }
    let fd = unsafe {
        libc::openat(
            workspace.as_raw_fd(),
            parsed.path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if parsed.absent {
        if fd >= 0 {
            unsafe { libc::close(fd) };
            return Err(LinuxCommandError::Unverified);
        }
        return (std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))
            .then_some(())
            .ok_or(LinuxCommandError::Unverified);
    }
    if fd < 0 {
        return Err(LinuxCommandError::Unverified);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut actual = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut actual) } != 0
        || actual.st_mode & libc::S_IFMT != libc::S_IFREG
        || actual.st_nlink != 1
        || actual.st_size < 0
    {
        return Err(LinuxCommandError::Unverified);
    }
    let expected = parsed
        .observation
        .target
        .ok_or(LinuxCommandError::Unverified)?;
    if actual.st_dev as u64 != expected.device
        || actual.st_ino as u64 != expected.inode
        || actual.st_size as u64 != expected.size
        || actual.st_mtime != expected.mtime_sec
        || actual.st_mtime_nsec != expected.mtime_nsec
        || actual.st_ctime != expected.ctime_sec
        || actual.st_ctime_nsec != expected.ctime_nsec
        || actual.st_size as u64 > HELPER_MAX_CONTENT as u64
    {
        return Err(LinuxCommandError::Unverified);
    }
    Ok(())
}
