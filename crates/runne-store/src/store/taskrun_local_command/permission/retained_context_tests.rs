//! Data roundtrips are not native scope or effect qualification.
#[path = "../../permission_modes/tests_capture_retention/fixture.rs"]
mod fixture;
#[path = "../../permission_modes/tests_capture_retention/target.rs"]
mod target;
use super::{codec, retained_context::*, retained_context_codec as wire};
use crate::store::PermissionModeSelectionSnapshot;
use runne_application::permission_modes::PermissionMode;
use runne_application::{permission_modes::*, project_trust::*};
use runne_domain::id::IntegrityDigest;

fn base() -> LocalCommandPermissionBindingV1 {
    let fixture = fixture::Fixture::new();
    let _ = &fixture.launch;
    target::capture(&fixture).0
}
fn rebuild(
    original: &LocalCommandPermissionBindingV1,
    scope: CompositeEffectScope,
    snapshot: ProjectTrustEffectPolicySnapshot,
    mode: PermissionMode,
    expiry: i64,
    relevant: [u8; 32],
) -> LocalCommandPermissionBindingV1 {
    let mut selection = original.selection().clone();
    selection.selected_mode = mode;
    rebuild_selected(original, scope, snapshot, selection, expiry, relevant)
}
fn rebuild_selected(
    original: &LocalCommandPermissionBindingV1,
    scope: CompositeEffectScope,
    snapshot: ProjectTrustEffectPolicySnapshot,
    selection: ModeSelection,
    expiry: i64,
    relevant: [u8; 32],
) -> LocalCommandPermissionBindingV1 {
    let mut approval = original.approval().clone();
    approval.composite_scope_digest = scope.digest().unwrap();
    approval.containment_version = scope.containment;
    approval.expires_at_unix_ms = expiry;
    approval.relevant_policy_digest = IntegrityDigest::from_bytes(relevant);
    LocalCommandPermissionBindingV1::checked(LocalCommandPermissionBindingInputV1 {
        selection,
        assignment: original.assignment().clone(),
        claim_stream_version: original.claim_stream_version(),
        invocation_id: original.invocation_id(),
        project_id: original.project_id(),
        project_version: original.project_version(),
        workspace_version: original.workspace_version(),
        admitted_root_version: original.admitted_root_version(),
        held_root_identity_digest: original.held_root_identity_digest(),
        command: original.command().clone(),
        command_intent_digest: original.command_intent_digest(),
        approval,
        scope,
        closed_rules_snapshot: snapshot,
        closed_rules_digest: IntegrityDigest::from_bytes(
            managed_effect_policy_digest_v2(
                ProjectTrustProjectId::from_bytes(*original.project_id().as_bytes()),
                &snapshot,
            )
            .unwrap(),
        ),
        limits: LocalInvocationLimitsV1::checked(0, 65536, u64::MAX).unwrap(),
    })
    .unwrap()
}
fn packet(binding: &LocalCommandPermissionBindingV1) -> (Vec<u8>, [u8; 32], CaptureContextRowV1) {
    let record = codec::CaptureV1::from_binding(
        binding,
        [7; 16],
        u64::MAX,
        &PermissionModeSelectionSnapshot {
            selection: binding.selection().clone(),
            managed_policy_version: binding.closed_rules_snapshot().record.revision,
            managed_policy_digest: binding.closed_rules_digest(),
        },
    )
    .unwrap();
    let bytes = codec::encode(&record).unwrap();
    let digest = codec::binding_digest(&bytes).unwrap();
    let row = CaptureContextRowV1 {
        taskrun_id: record.taskrun_id,
        attempt_id: record.attempt_id,
        invocation_id: record.invocation_id,
        fence: record.fence,
        binding_digest: digest,
        native_owner_id: record.native_owner_id,
        native_owner_generation: record.native_owner_generation,
        selection_managed_policy_version: record.selection_managed_policy_version,
        selection_managed_policy_digest: record.selection_managed_policy_digest,
    };
    (bytes, digest, row)
}
fn roundtrip(binding: &LocalCommandPermissionBindingV1) -> OriginalCaptureContextV1 {
    let (capture, digest, row) = packet(binding);
    let original = from_capture(binding, &capture, digest).unwrap();
    let bytes = wire::encode(&original).unwrap();
    let hash = wire::context_digest(&bytes).unwrap();
    let decoded = wire::decode_checked(&bytes, &hash, &capture, &digest, &row).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.scope, *binding.scope());
    assert_eq!(decoded.approval, *binding.approval());
    assert_eq!(decoded.closed_snapshot, binding.closed_rules_snapshot());
    assert_eq!(decoded.selection, *binding.selection());
    assert_eq!(decoded.limits, binding.limits());
    assert_eq!(wire::encode(&decoded).unwrap(), bytes);
    assert!(bytes.len() < 282000);
    decoded
}
include!("retained_context_shape_tests.rs");
include!("retained_context_corruption_tests.rs");
include!("retained_context_wire_fixture_tests.rs");
include!("retained_context_root_negative_tests.rs");
include!("retained_context_semantic_negative_tests.rs");
include!("retained_context_option_tests.rs");
include!("../../../schema/tests/v69_populated_context_states.rs");
pub(crate) fn with_migration_source(state: &str, run: impl FnOnce(&rusqlite::Connection, &[u8])) {
    let source = fixture::Fixture::new();
    let (binding, capture, _prepared) = target::capture(&source);
    prepare_state(&source, &binding, &capture, state);
    let writer = source.store.inner.writer.lock().unwrap();
    run(&writer, &capture.binding);
}
