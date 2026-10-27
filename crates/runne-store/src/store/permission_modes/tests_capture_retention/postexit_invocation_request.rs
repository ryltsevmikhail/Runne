//! Data-only original request correlation, never a restored native capability.
use super::metadata::Area;
use runne_application::permission_modes::{
    LocalCommandPermissionBindingInputV1, LocalCommandPermissionBindingV1,
};
use runne_domain::id::{IntegrityDigest, InvocationId};
use runne_platform::local_command_linux::PermissionTargetObservationV1;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestRecord {
    pub version: u8,
    pub role: String,
    pub area: Area,
    pub claim_stream_version: u64,
    pub approval_expires_at_unix_ms: i64,
    pub target_identity: [u8; 32],
    pub target_version: u64,
}
impl RequestRecord {
    pub fn of(area: &Area, binding: &LocalCommandPermissionBindingV1) -> Self {
        assert_eq!(binding.assignment(), &area.identity());
        assert_eq!(binding.invocation_id().to_string(), area.capture.invocation);
        assert_eq!(binding.digest().as_bytes(), &area.capture.canonical_digest);
        assert_eq!(
            binding.command_intent_digest().as_bytes(),
            &area.command_digest
        );
        Self {
            version: 1,
            role: "original-checked-request-data".into(),
            area: area.clone(),
            claim_stream_version: binding.claim_stream_version(),
            approval_expires_at_unix_ms: binding.approval().expires_at_unix_ms,
            target_identity: *binding.approval().target_identity_digest.as_bytes(),
            target_version: binding.approval().target_version,
        }
    }
    pub fn assert_original_and_fresh(
        &self,
        area: &Area,
        fresh: &LocalCommandPermissionBindingV1,
        observation: PermissionTargetObservationV1,
        now_unix_ms: i64,
    ) {
        assert_eq!(self.version, 1);
        assert_eq!(self.role, "original-checked-request-data");
        assert_eq!(&self.area, area);
        assert!(self.claim_stream_version > 0);
        assert!(self.approval_expires_at_unix_ms > now_unix_ms);
        assert_eq!(fresh.assignment(), &area.identity());
        assert_eq!(fresh.claim_stream_version(), self.claim_stream_version);
        assert_eq!(
            fresh.approval().expires_at_unix_ms,
            self.approval_expires_at_unix_ms
        );
        let old_id: InvocationId = area.capture.invocation.parse().unwrap();
        runne_domain::id::validate_uuid_v7_bytes(fresh.invocation_id().as_bytes()).unwrap();
        assert_ne!(fresh.invocation_id(), old_id);
        assert_ne!(observation.owner_id(), &[0; 16]);
        assert!(observation.owner_generation() > 0);
        assert_eq!(
            fresh.approval().target_identity_digest.as_bytes(),
            observation.target_identity()
        );
        assert_eq!(
            fresh.approval().target_version,
            observation.target_version()
        );
        assert_ne!(observation.target_identity(), &self.target_identity);
        let approval = fresh.approval();
        assert_eq!(
            approval.normalized_arguments_digest.as_bytes(),
            observation.normalized_arguments_digest()
        );
        assert_eq!(
            approval.tool_schema_digest.as_bytes(),
            observation.schema_digest()
        );
        assert_eq!(
            approval.environment_digest.as_bytes(),
            observation.environment_digest()
        );
        assert_eq!(
            approval.cwd_identity_digest.as_bytes(),
            observation.cwd_identity()
        );
        assert_eq!(
            approval.executable_digest.map(|d| *d.as_bytes()),
            Some(*observation.executable_digest())
        );
        assert!(
            fresh
                .selection()
                .expires_at_unix_ms
                .is_none_or(|expiry| expiry > now_unix_ms)
        );
        // Public checked DATA construction only. No original observation is forged.
        let mut original_input = input(fresh);
        original_input.invocation_id = old_id;
        original_input.approval.invocation.invocation_id = old_id;
        original_input.approval.target_identity_digest =
            IntegrityDigest::from_bytes(self.target_identity);
        original_input.approval.target_version = self.target_version;
        let original = LocalCommandPermissionBindingV1::checked(original_input).unwrap();
        assert_eq!(original.digest().as_bytes(), &area.capture.canonical_digest);
        assert_eq!(
            original.command_intent_digest().as_bytes(),
            &area.command_digest
        );
        assert_ne!(fresh.digest(), original.digest());
        assert!(
            !original
                .approval()
                .is_compatible_with(fresh.approval(), now_unix_ms)
        );
        // Exactly the two invocation fields and real fresh target fields differ.
        let mut expected = input(&original);
        expected.invocation_id = fresh.invocation_id();
        expected.approval.invocation.invocation_id = fresh.invocation_id();
        expected.approval.target_identity_digest = fresh.approval().target_identity_digest;
        expected.approval.target_version = observation.target_version();
        assert_eq!(input(fresh), expected);
    }
}
fn input(binding: &LocalCommandPermissionBindingV1) -> LocalCommandPermissionBindingInputV1 {
    LocalCommandPermissionBindingInputV1 {
        selection: binding.selection().clone(),
        assignment: binding.assignment().clone(),
        claim_stream_version: binding.claim_stream_version(),
        invocation_id: binding.invocation_id(),
        project_id: binding.project_id(),
        project_version: binding.project_version(),
        workspace_version: binding.workspace_version(),
        admitted_root_version: binding.admitted_root_version(),
        held_root_identity_digest: binding.held_root_identity_digest(),
        command: binding.command().clone(),
        command_intent_digest: binding.command_intent_digest(),
        approval: binding.approval().clone(),
        scope: binding.scope().clone(),
        closed_rules_snapshot: binding.closed_rules_snapshot(),
        closed_rules_digest: binding.closed_rules_digest(),
        limits: binding.limits(),
    }
}
