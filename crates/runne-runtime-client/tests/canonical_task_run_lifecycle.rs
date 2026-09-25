//! X2 conformance for the bounded public `TaskRun` client lifecycle.
//! Prompted submit is profile 3 / `/v2`; IDs-only submit remains the legacy
//! profile-compatible `/v1` method covered by `task_run_submit.rs`.

#[path = "task_run_read_support/mod.rs"]
mod support;

use runne_runtime_client::{
    CancelTaskRunRequest, CanonicalId, CommandIdentity, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH,
    REQUIRED_RUNTIME_CAPABILITIES, RuntimeApiErrorKind, RuntimeSessionInfo, SubmitTaskRunRequest,
    TaskRunState, mock_authenticated_runtime_client,
};

const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-0000000002a0";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-0000000002a1";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000002a2";
const COMMAND_ID: &str = "018f2e3a-7000-7000-8000-0000000002a3";
const CANCEL_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-0000000002a4";

fn id(value: &str) -> CanonicalId {
    CanonicalId::parse(value).expect("canonical ID")
}

fn identity(command_id: &str, key: &str) -> CommandIdentity {
    CommandIdentity::new(id(command_id), key).expect("command identity")
}

fn session() -> RuntimeSessionInfo {
    let capabilities = REQUIRED_RUNTIME_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    RuntimeSessionInfo {
        profile_id: EXPECTED_BUNDLE_ID.to_owned(),
        schema_hash: GOLDEN_BUNDLE_HASH.to_owned(),
        runtime_version: "test".to_owned(),
        capability_digest: capability_digest(&capabilities),
        capabilities,
        authority_id: "authority".to_owned(),
        principal_id: "principal".to_owned(),
        event_log_lineage_id: "lineage".to_owned(),
        daemon_instance_id: "daemon".to_owned(),
        launch_generation: 1,
        session_id: "session".to_owned(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: "certificate".to_owned(),
    }
}

fn capability_digest(values: &[String]) -> String {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(u32::try_from(values.len()).expect("count").to_be_bytes());
    for value in values {
        digest.update(u32::try_from(value.len()).expect("length").to_be_bytes());
        digest.update(value.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn ack(task_run_id: &str, version: u64, transition: &str) -> String {
    format!(
        "{{\"taskRunId\":\"{task_run_id}\",\"streamVersion\":{version},\"transition\":\"{transition}\",\"attemptId\":null,\"terminalResult\":null}}"
    )
}

include!("canonical_task_run_lifecycle_parts/lifecycle.rs");
include!("canonical_task_run_lifecycle_parts/surface.rs");
include!("canonical_task_run_lifecycle_parts/replay.rs");
