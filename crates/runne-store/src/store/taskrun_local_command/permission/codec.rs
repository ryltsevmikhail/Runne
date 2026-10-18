use super::super::super::permission_modes::PermissionModeSelectionSnapshot;
use runne_application::permission_modes::{LocalCommandPermissionBindingV1, PermissionMode};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"runne:d21:x2-permission-capture:v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureV1 {
    version: u8,
    pub(crate) canonical_binding_digest: [u8; 32],
    pub(crate) taskrun_id: [u8; 16],
    pub(crate) attempt_id: [u8; 16],
    pub(crate) node_id: String,
    pub(crate) node_epoch: u64,
    pub(crate) fence: u64,
    pub(crate) claim_stream_version: u64,
    pub(crate) invocation_id: [u8; 16],
    pub(crate) runtime_authority_id: String,
    pub(crate) principal_id: String,
    pub(crate) workspace_id: [u8; 16],
    pub(crate) project_id: [u8; 16],
    pub(crate) project_version: u64,
    pub(crate) workspace_version: u64,
    pub(crate) root_version: u64,
    pub(crate) root_identity: [u8; 32],
    pub(crate) trust_epoch: u64,
    pub(crate) trust_revision: u64,
    pub(crate) source_policy_version: u64,
    pub(crate) command_policy_version: u64,
    pub(crate) selected_mode: u8,
    pub(crate) preset_version: u16,
    pub(crate) authorization_revision: u64,
    pub(crate) selection_expires_at: Option<i64>,
    pub(crate) command_digest: [u8; 32],
    pub(crate) approval_digest: [u8; 32],
    pub(crate) scope_digest: [u8; 32],
    pub(crate) managed_policy_digest: [u8; 32],
    pub(crate) closed_rules_digest: [u8; 32],
    pub(crate) executable_digest: [u8; 32],
    pub(crate) target_identity: [u8; 32],
    pub(crate) target_version: u64,
    pub(crate) arguments_digest: [u8; 32],
    pub(crate) environment_digest: [u8; 32],
    pub(crate) cwd_identity: [u8; 32],
    pub(crate) tool_schema_digest: [u8; 32],
    pub(crate) stdout_limit: u64,
    pub(crate) stderr_limit: u64,
    pub(crate) max_runtime_ms: u64,
    pub(crate) native_owner_id: [u8; 16],
    pub(crate) native_owner_generation: u64,
    pub(crate) selection_managed_policy_version: u64,
    pub(crate) selection_managed_policy_digest: [u8; 32],
}

impl CaptureV1 {
    pub(crate) fn from_binding(
        binding: &LocalCommandPermissionBindingV1,
        owner_id: [u8; 16],
        owner_generation: u64,
        selection_snapshot: &PermissionModeSelectionSnapshot,
    ) -> Result<Self, ()> {
        let assignment = binding.assignment();
        let selection = binding.selection();
        let approval = binding.approval();
        let scope = binding.scope();
        let limits = binding.limits();
        let target = approval.target_identity_digest;
        let executable = approval.executable_digest.ok_or(())?;
        let snapshot = binding.closed_rules_snapshot();
        if selection_snapshot.selection != *selection {
            return Err(());
        }
        let record = Self {
            version: 1,
            canonical_binding_digest: *binding.digest().as_bytes(),
            taskrun_id: *assignment.taskrun_id.as_bytes(),
            attempt_id: *assignment.attempt_id.as_bytes(),
            node_id: assignment.node_id.0.clone(),
            node_epoch: assignment.node_epoch,
            fence: assignment.fence.0,
            claim_stream_version: binding.claim_stream_version(),
            invocation_id: *binding.invocation_id().as_bytes(),
            runtime_authority_id: selection.scope.runtime_authority_id.0.clone(),
            principal_id: selection.scope.principal_id.as_str().to_owned(),
            workspace_id: *selection.scope.workspace_id.as_bytes(),
            project_id: *binding.project_id().as_bytes(),
            project_version: binding.project_version(),
            workspace_version: binding.workspace_version(),
            root_version: binding.admitted_root_version(),
            root_identity: *binding.held_root_identity_digest().as_bytes(),
            trust_epoch: snapshot.record.instance_epoch,
            trust_revision: snapshot.record.revision,
            source_policy_version: runne_application::project_trust::FROZEN_POLICY_VERSION,
            command_policy_version: runne_application::project_trust::LOCAL_COMMAND_POLICY_VERSION,
            selected_mode: mode_tag(selection.selected_mode),
            preset_version: selection.preset_version.as_u16(),
            authorization_revision: selection.authorization_revision,
            selection_expires_at: selection.expires_at_unix_ms,
            command_digest: *binding.command_intent_digest().as_bytes(),
            approval_digest: *approval.digest().as_bytes(),
            scope_digest: *scope.digest().map_err(|_| ())?.as_bytes(),
            managed_policy_digest: *scope.managed_policy.policy_digest().as_bytes(),
            closed_rules_digest: *binding.closed_rules_digest().as_bytes(),
            executable_digest: *executable.as_bytes(),
            target_identity: *target.as_bytes(),
            target_version: approval.target_version,
            arguments_digest: *approval.normalized_arguments_digest.as_bytes(),
            environment_digest: *approval.environment_digest.as_bytes(),
            cwd_identity: *approval.cwd_identity_digest.as_bytes(),
            tool_schema_digest: *approval.tool_schema_digest.as_bytes(),
            stdout_limit: limits.stdout_capture_bytes(),
            stderr_limit: limits.stderr_capture_bytes(),
            max_runtime_ms: limits.max_runtime_ms(),
            native_owner_id: owner_id,
            native_owner_generation: owner_generation,
            selection_managed_policy_version: selection_snapshot.managed_policy_version,
            selection_managed_policy_digest: *selection_snapshot.managed_policy_digest.as_bytes(),
        };
        if owner_id.iter().all(|byte| *byte == 0)
            || owner_generation == 0
            || record
                .canonical_binding_digest
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(());
        }
        Ok(record)
    }
}

pub(crate) fn encode(record: &CaptureV1) -> Result<Vec<u8>, ()> {
    let bytes = serde_json::to_vec(record).map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(());
    }
    Ok(bytes)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<CaptureV1, ()> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(());
    }
    let record: CaptureV1 = serde_json::from_slice(bytes).map_err(|_| ())?;
    if record.version != 1
        || record.native_owner_id.iter().all(|byte| *byte == 0)
        || record.native_owner_generation == 0
        || record
            .canonical_binding_digest
            .iter()
            .all(|byte| *byte == 0)
        || encode(&record)?.as_slice() != bytes
    {
        return Err(());
    }
    Ok(record)
}

pub(crate) fn binding_digest(bytes: &[u8]) -> Result<[u8; 32], ()> {
    decode(bytes)?;
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    Ok(hash.finalize().into())
}

pub(crate) fn mode_tag(mode: PermissionMode) -> u8 {
    match mode {
        PermissionMode::AskAlways => 1,
        PermissionMode::RiskBased => 2,
        PermissionMode::FullAccess => 3,
    }
}

pub(crate) fn digest_matches(bytes: &[u8], digest: &[u8]) -> bool {
    binding_digest(bytes).is_ok_and(|value| value.as_slice() == digest)
}
