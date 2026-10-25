use super::{
    codec::CaptureV1,
    retained_context::{
        CaptureContextRowV1, ContextErrorV1, OriginalCaptureContextV1, derive_projection,
    },
};
use ContextErrorV1::{CorrelationMismatch, InvalidOriginalData};
use runne_application::{
    permission_modes::*,
    project_trust::{ProjectTrustProjectId, managed_effect_policy_digest_v2},
};
use runne_domain::id::{AttemptId, IntegrityDigest, InvocationId, TaskRunId, WorkspaceId};
use sha2::{Digest, Sha256};

pub(super) fn reconstruct(
    c: &CaptureV1,
    scope: &CompositeEffectScope,
    expiry: i64,
    relevant: [u8; 32],
) -> Result<(ApprovalBinding, ModeSelection, LocalInvocationLimitsV1), ContextErrorV1> {
    if expiry <= 0
        || c.selection_expires_at.is_some_and(|value| value <= 0)
        || c.preset_version != 1
    {
        return Err(InvalidOriginalData);
    }
    let permission_scope = PermissionScope {
        runtime_authority_id: runne_application::ports::RuntimeAuthorityId(
            c.runtime_authority_id.clone(),
        ),
        principal_id: runne_api::ApiPrincipalId::new(c.principal_id.clone())
            .map_err(|_| InvalidOriginalData)?,
        workspace_id: WorkspaceId::from_bytes(c.workspace_id),
    };
    if permission_scope != scope.permission_scope {
        return Err(CorrelationMismatch);
    }
    let approval = ApprovalBinding {
        action: PermissionAction::ProcessStart,
        normalized_arguments_digest: IntegrityDigest::from_bytes(c.arguments_digest),
        tool_schema_digest: IntegrityDigest::from_bytes(c.tool_schema_digest),
        principal_id: permission_scope.principal_id.clone(),
        invocation: InvocationIdentity {
            task_run_id: TaskRunId::from_bytes(c.taskrun_id),
            attempt_id: AttemptId::from_bytes(c.attempt_id),
            invocation_id: InvocationId::from_bytes(c.invocation_id),
        },
        target_identity_digest: IntegrityDigest::from_bytes(c.target_identity),
        target_version: c.target_version,
        environment_digest: IntegrityDigest::from_bytes(c.environment_digest),
        cwd_identity_digest: IntegrityDigest::from_bytes(c.cwd_identity),
        executable_digest: Some(IntegrityDigest::from_bytes(c.executable_digest)),
        composite_scope_digest: scope.digest().map_err(|_| InvalidOriginalData)?,
        containment_version: scope.containment,
        relevant_policy_digest: IntegrityDigest::from_bytes(relevant),
        expires_at_unix_ms: expiry,
    };
    let selection = ModeSelection {
        scope: permission_scope,
        selected_mode: match c.selected_mode {
            1 => PermissionMode::AskAlways,
            2 => PermissionMode::RiskBased,
            3 => PermissionMode::FullAccess,
            _ => return Err(InvalidOriginalData),
        },
        preset_version: PresetVersion::V1,
        authorization_revision: c.authorization_revision,
        expires_at_unix_ms: c.selection_expires_at,
    };
    let limits = LocalInvocationLimitsV1::checked(c.stdout_limit, c.stderr_limit, c.max_runtime_ms)
        .map_err(|_| InvalidOriginalData)?;
    Ok((approval, selection, limits))
}

pub(super) fn validate(
    context: &OriginalCaptureContextV1,
    c: &CaptureV1,
    digest: &[u8; 32],
    row: &CaptureContextRowV1,
) -> Result<(), ContextErrorV1> {
    let project = ProjectTrustProjectId::from_bytes(c.project_id);
    let snapshot = &context.closed_snapshot;
    let closed = managed_effect_policy_digest_v2(project, snapshot).ok_or(InvalidOriginalData)?;
    let scope_digest = context.scope.digest().map_err(|_| InvalidOriginalData)?;
    let (approval, selection, limits) = reconstruct(
        c,
        &context.scope,
        context.approval.expires_at_unix_ms,
        *context.approval.relevant_policy_digest.as_bytes(),
    )?;
    let projection = derive_projection(
        project,
        &context.scope,
        snapshot,
        context.preset_version,
        context.source_policy_version,
        context.command_policy_version,
    )?;
    let canonical = canonical_binding_digest_from_capture(
        c,
        scope_digest,
        IntegrityDigest::from_bytes(closed),
        approval.digest(),
        limits,
    )?;
    if context.capture_digest != *digest
        || *digest != row.binding_digest
        || context.canonical_binding_digest != c.canonical_binding_digest
        || canonical.as_bytes() != &c.canonical_binding_digest
        || context.source_policy_version != 2
        || c.source_policy_version != 2
        || context.command_policy_version != 1
        || c.command_policy_version != 1
        || context.preset_version != 1
        || c.preset_version != 1
        || snapshot.record.instance_epoch != c.trust_epoch
        || snapshot.record.revision != c.trust_revision
        || closed != c.closed_rules_digest
        || closed != c.managed_policy_digest
        || scope_digest.as_bytes() != &c.scope_digest
        || approval.digest().as_bytes() != &c.approval_digest
        || approval != context.approval
        || selection != context.selection
        || limits != context.limits
        || projection != context.semantic_projection
        || c.taskrun_id != row.taskrun_id
        || c.attempt_id != row.attempt_id
        || c.invocation_id != row.invocation_id
        || c.fence != row.fence
        || c.native_owner_id != row.native_owner_id
        || c.native_owner_generation != row.native_owner_generation
        || c.selection_managed_policy_version != snapshot.record.revision
        || c.selection_managed_policy_version != row.selection_managed_policy_version
        || c.selection_managed_policy_digest != closed
        || c.selection_managed_policy_digest != row.selection_managed_policy_digest
    {
        return Err(CorrelationMismatch);
    }
    Ok(())
}

pub(super) fn canonical_binding_digest_from_capture(
    c: &CaptureV1,
    scope: CompositeScopeDigest,
    closed: IntegrityDigest,
    approval: IntegrityDigest,
    limits: LocalInvocationLimitsV1,
) -> Result<IntegrityDigest, ContextErrorV1> {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:local-command-permission-binding:v1\0");
    for version in [1u16, 1, 2] {
        hash.update(version.to_be_bytes());
    }
    hash.update(2u64.to_be_bytes());
    hash.update(1u64.to_be_bytes());
    put_bytes(&mut hash, c.runtime_authority_id.as_bytes())?;
    put_bytes(&mut hash, c.principal_id.as_bytes())?;
    hash.update(c.workspace_id);
    hash.update([c.selected_mode]);
    hash.update(c.preset_version.to_be_bytes());
    hash.update(c.authorization_revision.to_be_bytes());
    match c.selection_expires_at {
        None => hash.update([0]),
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
    }
    hash.update(c.taskrun_id);
    hash.update(c.attempt_id);
    put_bytes(&mut hash, c.node_id.as_bytes())?;
    for number in [c.node_epoch, c.fence, c.claim_stream_version] {
        hash.update(number.to_be_bytes());
    }
    hash.update(c.invocation_id);
    hash.update(c.project_id);
    for number in [c.project_version, c.workspace_version, c.root_version] {
        hash.update(number.to_be_bytes());
    }
    hash.update(c.root_identity);
    hash.update(c.command_digest);
    hash.update(approval.as_bytes());
    hash.update(scope.as_bytes());
    hash.update(closed.as_bytes());
    let mut bound = Sha256::new();
    bound.update(b"runne:d21:local-invocation-limits:v1\0");
    bound.update(1u16.to_be_bytes());
    bound.update([limits.admitted_invocations()]);
    for number in [
        limits.stdout_capture_bytes(),
        limits.stderr_capture_bytes(),
        limits.max_runtime_ms(),
    ] {
        bound.update(number.to_be_bytes());
    }
    hash.update(bound.finalize());
    Ok(IntegrityDigest::from_bytes(hash.finalize().into()))
}
fn put_bytes(hash: &mut Sha256, bytes: &[u8]) -> Result<(), ContextErrorV1> {
    hash.update(
        u32::try_from(bytes.len())
            .map_err(|_| InvalidOriginalData)?
            .to_be_bytes(),
    );
    hash.update(bytes);
    Ok(())
}
