mod model;
mod read;
mod recovery;
mod validate;
mod write;

pub use model::*;
pub use read::ToolInvocationLookup;
pub use recovery::ToolInvocationAreaRecoveryCandidate;

use super::StoreTransaction;
use runne_application::ports::TaskRunAssignmentIdentity;
use runne_domain::{id::TaskRunId, reference::BudgetReservationRef};

impl StoreTransaction {
    pub fn ensure_taskrun_tool_loop_budget(
        &self,
        taskrun_id: TaskRunId,
        expected_version: u64,
        assignment: &TaskRunAssignmentIdentity,
        now_unix_ms: i64,
    ) -> Result<BudgetReservationRef, ToolInvocationStoreError> {
        write::ensure_budget(self, taskrun_id, expected_version, assignment, now_unix_ms)
    }

    pub fn load_taskrun_tool_loop_budget_ref(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<Option<BudgetReservationRef>, ToolInvocationStoreError> {
        read::load_budget_ref(self, taskrun_id)
    }

    pub fn propose_taskrun_tool_invocation(
        &self,
        binding: ToolInvocationBindingV1,
        arguments_payload: EncryptedToolPayloadV1,
        assignment: &TaskRunAssignmentIdentity,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::propose(self, binding, arguments_payload, assignment, now_unix_ms)
    }

    /// Persists a proposal and its exact permission admission in one transaction.
    pub fn propose_taskrun_tool_invocation_with_permission(
        &self,
        binding: ToolInvocationBindingV1,
        arguments_payload: EncryptedToolPayloadV1,
        permission: ToolPermissionAdmissionV1,
        assignment: &TaskRunAssignmentIdentity,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::propose_with_permission(
            self,
            binding,
            arguments_payload,
            permission,
            assignment,
            now_unix_ms,
        )
    }

    /// Marks an already-persisted preset-allowed invocation as admitted.
    pub fn admit_taskrun_tool_permission_automatically(
        &self,
        key: ToolInvocationKey,
        semantic_digest: IntegrityDigest,
        assignment: &TaskRunAssignmentIdentity,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::admit_automatically(self, key, semantic_digest, assignment, now_unix_ms)
    }

    /// Binds an already-decided approval row; this method never decides approval.
    pub fn bind_taskrun_tool_approval(
        &self,
        approval: ToolApprovalBindingV1,
        assignment: &TaskRunAssignmentIdentity,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::bind_approval(self, approval, assignment, now_unix_ms)
    }

    pub fn claim_taskrun_tool_invocation(
        &self,
        key: ToolInvocationKey,
        semantic_digest: IntegrityDigest,
        assignment: &TaskRunAssignmentIdentity,
        expected_taskrun_version: u64,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::claim(
            self,
            key,
            semantic_digest,
            assignment,
            expected_taskrun_version,
            now_unix_ms,
        )
    }

    pub fn mark_taskrun_tool_invocation_uncertain(
        &self,
        key: ToolInvocationKey,
        semantic_digest: IntegrityDigest,
        assignment: &TaskRunAssignmentIdentity,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::mark_uncertain(self, key, semantic_digest, assignment, now_unix_ms)
    }

    pub fn record_taskrun_tool_result(
        &self,
        receipt: TrustedToolReceiptV1,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::record_result(self, receipt, now_unix_ms)
    }

    /// Persists bounded encrypted failure evidence after local stop proof fails.
    /// The row is forced to AuditOnly and cannot feed a continuation.
    pub fn record_taskrun_tool_audit_payload(
        &self,
        receipt: TrustedToolReceiptV1,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::record_audit_payload(self, receipt, now_unix_ms)
    }

    pub fn record_taskrun_tool_area_launch(
        &self,
        key: ToolInvocationKey,
        semantic_digest: IntegrityDigest,
        assignment: &TaskRunAssignmentIdentity,
        identity: &runne_platform::process_managed_area::ManagedAreaIdentity,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::record_area_launch(
            self,
            key,
            semantic_digest,
            assignment,
            identity,
            now_unix_ms,
        )
    }

    pub fn record_taskrun_tool_area_stopped(
        &self,
        key: ToolInvocationKey,
        semantic_digest: IntegrityDigest,
        assignment: &TaskRunAssignmentIdentity,
        identity: &runne_platform::process_managed_area::ManagedAreaIdentity,
        proof: &runne_platform::process_managed_area::VerifiedEmptyManagedArea<'_>,
        now_unix_ms: i64,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        write::record_area_stopped(
            self,
            key,
            semantic_digest,
            assignment,
            identity,
            proof,
            now_unix_ms,
        )
    }

    pub fn with_taskrun_tool_invocation_release<T, E, F>(
        &self,
        key: ToolInvocationKey,
        semantic_digest: IntegrityDigest,
        assignment: &TaskRunAssignmentIdentity,
        now_unix_ms: i64,
        release: F,
    ) -> Result<Result<T, E>, ToolInvocationStoreError>
    where
        F: FnOnce() -> Result<T, E>,
    {
        write::with_release(self, key, semantic_digest, assignment, now_unix_ms, release)
    }

    pub fn get_taskrun_tool_invocation(
        &self,
        key: ToolInvocationKey,
    ) -> Result<Option<ToolInvocationReceipt>, ToolInvocationStoreError> {
        read::get(self, key)
    }

    pub fn load_taskrun_tool_invocation(
        &self,
        key: ToolInvocationKey,
    ) -> Result<Option<ToolInvocationStoredRecord>, ToolInvocationStoreError> {
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        read::load_record(&reader, key)
    }

    /// Loads the immutable permission admission attached to one invocation.
    pub fn load_taskrun_tool_permission_admission(
        &self,
        key: ToolInvocationKey,
    ) -> Result<Option<ToolPermissionAdmissionV1>, ToolInvocationStoreError> {
        write::load_permission(self, key)
    }

    pub fn load_taskrun_tool_invocations_for_taskrun(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<Vec<ToolInvocationStoredRecord>, ToolInvocationStoreError> {
        read::list_for_taskrun(self, taskrun_id)
    }
}

use runne_domain::id::IntegrityDigest;

impl ToolInvocationBindingV1 {
    /// Recomputes the argument and semantic digests after the binding is assembled.
    pub fn refresh_digests(&mut self) {
        self.arguments_digest = validate::hash(&self.canonical_arguments);
        self.semantic_digest = validate::semantic_digest(self);
    }
}
