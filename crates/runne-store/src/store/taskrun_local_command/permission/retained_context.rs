//! Store-private original evidence; never a native authority or admission.
use runne_application::{
    permission_modes::{
        ApprovalBinding, CompositeEffectScope, LocalCommandPermissionBindingV1,
        LocalInvocationLimitsV1, ModeSelection, RetainedScopeSemanticsV1,
    },
    project_trust::ProjectTrustEffectPolicySnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OriginalCaptureContextV1 {
    pub(super) capture_digest: [u8; 32],
    pub(super) canonical_binding_digest: [u8; 32],
    pub(super) source_policy_version: u64,
    pub(super) command_policy_version: u64,
    pub(super) preset_version: u16,
    pub(super) scope: CompositeEffectScope,
    pub(super) closed_snapshot: ProjectTrustEffectPolicySnapshot,
    pub(super) approval: ApprovalBinding,
    pub(super) selection: ModeSelection,
    pub(super) limits: LocalInvocationLimitsV1,
    pub(super) semantic_projection: OriginalSemanticProjectionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContextErrorV1 {
    MalformedWire,
    UnsupportedWireVersion,
    CorrelationMismatch,
    InvalidOriginalData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureContextRowV1 {
    pub(crate) taskrun_id: [u8; 16],
    pub(crate) attempt_id: [u8; 16],
    pub(crate) invocation_id: [u8; 16],
    pub(crate) fence: u64,
    pub(crate) binding_digest: [u8; 32],
    pub(crate) native_owner_id: [u8; 16],
    pub(crate) native_owner_generation: u64,
    pub(crate) selection_managed_policy_version: u64,
    pub(crate) selection_managed_policy_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OriginalSemanticProjectionV1 {
    SupportedV1(runne_application::permission_modes::RetainedRelevantSemanticsV1),
    UnsupportedV1,
}

pub(super) fn derive_projection(
    project: runne_application::project_trust::ProjectTrustProjectId,
    scope: &CompositeEffectScope,
    snapshot: &ProjectTrustEffectPolicySnapshot,
    preset: u16,
    source: u64,
    command: u64,
) -> Result<OriginalSemanticProjectionV1, ContextErrorV1> {
    match runne_application::permission_modes::derive_original_semantics_v1(
        project, scope, snapshot, preset, source, command,
    )
    .map_err(|_| ContextErrorV1::InvalidOriginalData)?
    {
        RetainedScopeSemanticsV1::SupportedV1(value) => {
            Ok(OriginalSemanticProjectionV1::SupportedV1(value))
        }
        RetainedScopeSemanticsV1::UnsupportedV1(_) => {
            Ok(OriginalSemanticProjectionV1::UnsupportedV1)
        }
    }
}

pub(crate) fn from_capture(
    binding: &LocalCommandPermissionBindingV1,
    bytes: &[u8],
    digest: [u8; 32],
) -> Result<OriginalCaptureContextV1, ContextErrorV1> {
    let capture = super::codec::decode(bytes).map_err(|_| ContextErrorV1::MalformedWire)?;
    if super::codec::binding_digest(bytes).map_err(|_| ContextErrorV1::MalformedWire)? != digest {
        return Err(ContextErrorV1::CorrelationMismatch);
    }
    let snapshot = binding.closed_rules_snapshot();
    let project = runne_application::project_trust::ProjectTrustProjectId::from_bytes(
        *binding.project_id().as_bytes(),
    );
    let context = OriginalCaptureContextV1 {
        capture_digest: digest,
        canonical_binding_digest: *binding.digest().as_bytes(),
        source_policy_version: 2,
        command_policy_version: 1,
        preset_version: binding.selection().preset_version.as_u16(),
        scope: binding.scope().clone(),
        closed_snapshot: snapshot,
        approval: binding.approval().clone(),
        selection: binding.selection().clone(),
        limits: binding.limits(),
        semantic_projection: derive_projection(project, binding.scope(), &snapshot, 1, 2, 1)?,
    };
    let row = CaptureContextRowV1 {
        taskrun_id: *binding.assignment().taskrun_id.as_bytes(),
        attempt_id: *binding.assignment().attempt_id.as_bytes(),
        invocation_id: *binding.invocation_id().as_bytes(),
        fence: binding.assignment().fence.0,
        binding_digest: digest,
        native_owner_id: capture.native_owner_id,
        native_owner_generation: capture.native_owner_generation,
        selection_managed_policy_version: snapshot.record.revision,
        selection_managed_policy_digest: *binding.closed_rules_digest().as_bytes(),
    };
    validate_correlation(&context, &capture, &digest, &row)?;
    Ok(context)
}

pub(crate) fn validate_correlation(
    context: &OriginalCaptureContextV1,
    capture: &super::codec::CaptureV1,
    digest: &[u8; 32],
    row: &CaptureContextRowV1,
) -> Result<(), ContextErrorV1> {
    super::retained_context_correlation::validate(context, capture, digest, row)
}

pub(crate) fn validate_optional_context_pair(
    context: Option<&[u8]>,
    digest: Option<&[u8]>,
    capture: &[u8],
    capture_digest: &[u8; 32],
    row: &CaptureContextRowV1,
) -> Result<Option<OriginalCaptureContextV1>, ContextErrorV1> {
    match (context, digest) {
        (None, None) => Ok(None),
        (Some(bytes), Some(digest)) => {
            let digest = digest
                .try_into()
                .map_err(|_| ContextErrorV1::MalformedWire)?;
            super::retained_context_codec::decode_checked(
                bytes,
                digest,
                capture,
                capture_digest,
                row,
            )
            .map(Some)
        }
        _ => Err(ContextErrorV1::MalformedWire),
    }
}
