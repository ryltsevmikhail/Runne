use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityV1 {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionV1 {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingV1 {
    pub taskrun_id: String,
    pub attempt_id: String,
    pub cycle_id: String,
    pub proposal_index: u32,
    pub taskrun_version: u64,
    pub assignment_fence: u64,
    pub invocation_digest: String,
    pub environment_digest: String,
    pub approval_digest: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub(crate) enum RequestV1 {
    Coding {
        binding: BindingV1,
        tool_name: String,
        arguments: serde_json::Value,
        root: IdentityV1,
        expected: Option<VersionV1>,
    },
    Read {
        binding: BindingV1,
        path: String,
        root: IdentityV1,
        expected: VersionV1,
    },
    CreateNew {
        binding: BindingV1,
        path: String,
        root: IdentityV1,
        expected_absent: bool,
        content_base64: String,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptV1 {
    pub status: String,
    pub version: u8,
    pub operation: String,
    pub path: String,
    pub binding: BindingV1,
    pub root: IdentityV1,
    pub target: VersionV1,
    pub bytes_base64: String,
    pub byte_length: usize,
    pub truncated: bool,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorV1 {
    pub status: String,
    pub version: u8,
    pub error: String,
    pub effect_started: bool,
}
