use runne_api::{
    ApiPrincipalId, ApprovalCreateCommand, ApprovalQueryContext, ApprovalQueryHostPort,
    ApprovalRequestHostPort, ApprovalState,
};
use runne_domain::id::{ApprovalId, AttemptId, InvocationId, TaskRunId};
use runne_store::ProjectWorkspaceStore;
use sha2::{Digest, Sha256};

#[path = "tool_invocation/effect.rs"]
mod effect;
#[path = "tool_invocation/permission.rs"]
mod permission;
#[path = "tool_invocation/permission_build.rs"]
mod permission_build;
#[path = "tool_invocation/permission_identity.rs"]
mod permission_identity;
#[path = "tool_invocation/proposal.rs"]
mod proposal;
#[path = "tool_invocation/target_snapshot.rs"]
pub(crate) mod target_snapshot;

const ACTION: &str = "workspace.tool.invoke";
const POLICY_REVISION: u64 = 1;
const RENDERER_GENERATION: u64 = 1;
const APPROVAL_TTL_MS: i64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ApprovalDisposition {
    Pending,
    Approved,
    Denied,
}

pub(super) fn parse_fixed_arguments(
    call: &runne_runtime::provider_tool::RuntimeToolCall,
) -> Result<(String, Vec<u8>), ()> {
    if call.arguments_json.len() > 8 * 1024 || call.call_id.is_empty() || call.call_id.len() > 128 {
        return Err(());
    }
    let value: serde_json::Value = serde_json::from_str(&call.arguments_json).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    let path = object.get("path").and_then(|v| v.as_str()).ok_or(())?;
    if path.is_empty()
        || path.len() > 255
        || path == "."
        || path == ".."
        || path.contains('/')
        || path.contains('\\')
        || path.as_bytes().contains(&0)
    {
        return Err(());
    }
    let content = match call.tool_name.as_str() {
        "workspace.file.read" if object.len() == 1 => Vec::new(),
        "workspace.file.create_new" if object.len() == 2 => {
            use base64::Engine;
            let encoded = object
                .get("content_base64")
                .and_then(|v| v.as_str())
                .ok_or(())?;
            if encoded.len() > 8 * 1024 {
                return Err(());
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| ())?;
            if decoded.len() > 8 * 1024 {
                return Err(());
            }
            decoded
        }
        _ => return Err(()),
    };
    Ok((path.to_owned(), content))
}

pub(super) fn parse_arguments(
    call: &runne_runtime::provider_tool::RuntimeToolCall,
    coding: bool,
) -> Result<(String, Vec<u8>), ()> {
    if !coding {
        return parse_fixed_arguments(call);
    }
    if call.arguments_json.len() > 8192 || call.call_id.is_empty() || call.call_id.len() > 128 {
        return Err(());
    }
    let value = serde_json::from_str(&call.arguments_json).map_err(|_| ())?;
    let args = crate::safe_tool_helper::coding_arguments::parse(&call.tool_name, &value)?;
    Ok((args.path, args.content))
}

// Each independent approval authority and precondition is committed into this digest.
#[allow(clippy::too_many_arguments)]
pub(super) fn approval_digest(
    taskrun: TaskRunId,
    attempt: AttemptId,
    cycle: runne_domain::id::CycleId,
    proposal_index: u32,
    taskrun_head: u64,
    call_id: &str,
    tool_name: &str,
    tool_revision: &str,
    environment_id: &str,
    approval_principal: &str,
    schema_digest: &[u8; 32],
    canonical_arguments: &[u8],
    target_precondition: Option<&[u8; 32]>,
    root_identity: &[u8; 32],
    root_revision: u64,
    workspace_version: u64,
    trust_epoch: u64,
    trust_revision: u64,
    expires_at: i64,
    helper_executable: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"RUNNE_D2_HUMAN_TOOL_APPROVAL_V1\0");
    hash.update(taskrun.as_bytes());
    hash.update(attempt.as_bytes());
    hash.update(cycle.as_bytes());
    hash.update(proposal_index.to_be_bytes());
    hash.update(taskrun_head.to_be_bytes());
    put(&mut hash, call_id.as_bytes());
    put(&mut hash, tool_name.as_bytes());
    put(&mut hash, tool_revision.as_bytes());
    put(&mut hash, environment_id.as_bytes());
    put(&mut hash, approval_principal.as_bytes());
    hash.update(schema_digest);
    put(&mut hash, canonical_arguments);
    hash.update(target_precondition.copied().unwrap_or([0; 32]));
    hash.update(root_identity);
    hash.update(root_revision.to_be_bytes());
    hash.update(workspace_version.to_be_bytes());
    hash.update(trust_epoch.to_be_bytes());
    hash.update(trust_revision.to_be_bytes());
    hash.update(expires_at.to_be_bytes());
    if let Some(image) = helper_executable {
        hash.update(b"RUNNE_CODING_PROCESS_HELPER_V1\0");
        hash.update(image);
    }
    hash.finalize().into()
}

fn put(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

// Compare every immutable binding field against the durable human approval row.
#[allow(clippy::too_many_arguments)]
pub(super) async fn ensure_human_approval(
    store: ProjectWorkspaceStore,
    taskrun: TaskRunId,
    attempt: AttemptId,
    approval_id: [u8; 16],
    invocation_id: [u8; 16],
    principal: ApiPrincipalId,
    resource: String,
    action_digest: [u8; 32],
    expires_at: i64,
    risk_summary: String,
) -> Result<ApprovalDisposition, ()> {
    let id = ApprovalId::from_bytes(approval_id);
    let summary = match store
        .get_approval(
            ApprovalQueryContext {
                principal: principal.clone(),
            },
            id,
        )
        .await
    {
        Ok(summary) => summary,
        Err(runne_api::ApprovalHostError::NotFound) => {
            let command = ApprovalCreateCommand::new(
                id,
                taskrun,
                Some(attempt),
                InvocationId::from_bytes(invocation_id),
                principal,
                ACTION,
                resource.clone(),
                action_digest,
                POLICY_REVISION,
                RENDERER_GENERATION,
                expires_at,
                risk_summary,
            )
            .map_err(|_| ())?;
            store
                .create_pending_approval(command)
                .await
                .map_err(|_| ())?
        }
        Err(_) => return Err(()),
    };
    if summary.task_run_id() != taskrun
        || summary.attempt_id() != Some(attempt)
        || summary.invocation_id().as_bytes() != &invocation_id
        || summary.action() != ACTION
        || summary.resource() != resource
        || summary.action_digest() != &action_digest
        || summary.policy_revision() != POLICY_REVISION
        || summary.expires_at() != expires_at
        || summary.expires_at() <= now_millis()
    {
        return Err(());
    }
    match summary.state() {
        ApprovalState::Pending => Ok(ApprovalDisposition::Pending),
        ApprovalState::Approved => Ok(ApprovalDisposition::Approved),
        ApprovalState::Denied | ApprovalState::Expired | ApprovalState::Cancelled => {
            Ok(ApprovalDisposition::Denied)
        }
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_domain::id::{AttemptId, CycleId, IntegrityDigest, TaskRunId};
    use runne_store::store::taskrun_tool_invocation::ToolInvocationKey;

    #[test]
    fn fixed_tool_arguments_reject_extra_scope_and_bound_content() {
        let mut call = runne_runtime::provider_tool::RuntimeToolCall {
            call_id: "call-1".into(),
            tool_name: "workspace.file.read".into(),
            arguments_json: r#"{"path":"note.txt"}"#.into(),
        };
        assert_eq!(parse_fixed_arguments(&call).unwrap().0, "note.txt");
        call.arguments_json = r#"{"path":"../secret"}"#.into();
        assert!(parse_fixed_arguments(&call).is_err());
        call.arguments_json = r#"{"path":"note.txt","absolute":true}"#.into();
        assert!(parse_fixed_arguments(&call).is_err());
    }

    #[test]
    fn invocation_area_nonce_is_distinct_for_each_exact_cycle_index() {
        let key = ToolInvocationKey {
            taskrun_id: TaskRunId::from_bytes([1; 16]),
            attempt_id: AttemptId::from_bytes([2; 16]),
            cycle_id: CycleId::from_bytes([3; 16]),
            proposal_index: 0,
        };
        let digest = IntegrityDigest::from_bytes([4; 32]);
        let mut next = key;
        next.proposal_index = 1;
        assert_ne!(
            key.managed_area_nonce(digest),
            next.managed_area_nonce(digest)
        );
    }
}

#[cfg(test)]
#[path = "tool_invocation/image_approval_tests.rs"]
mod image_approval_tests;
