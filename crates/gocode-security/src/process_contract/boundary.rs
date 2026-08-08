//! Immutable per-call facade over shared authorization authority state.

use super::authority::ProcessAuthorizationAuthorityV1;
use super::authorization::{
    approval_scope, approve_bound, issue_capability, preflight_authorization,
    validate_authorization,
};
use super::context::CurrentProcessContextV1;
use super::{
    ProcessApprovalV1, ProcessCapabilityId, ProcessCapabilityV1, ProcessContractError,
    ProcessIntentV1, ValidatedProcessIntentV1,
};

/// Opaque immutable context for one exact lifecycle binding.
pub struct ProcessAuthorizationBoundaryV1 {
    authority: ProcessAuthorizationAuthorityV1,
    context: CurrentProcessContextV1,
}

impl ProcessAuthorizationBoundaryV1 {
    pub(super) fn bound(
        authority: ProcessAuthorizationAuthorityV1,
        context: CurrentProcessContextV1,
    ) -> Self {
        Self { authority, context }
    }

    pub fn issue_capability(
        &self,
        intent: &ProcessIntentV1,
        expires: u64,
    ) -> Result<ProcessCapabilityV1, ProcessContractError> {
        let mut state = self.authority.lock_for(&self.context)?;
        let counter = state
            .capability_counter
            .checked_add(1)
            .ok_or(ProcessContractError::CapabilityInvalid)?;
        let mut id = [0; 16];
        id[..8].copy_from_slice(
            &state
                .replay_guard
                .domain()
                .authority_instance()
                .to_be_bytes(),
        );
        id[8..].copy_from_slice(&counter.to_be_bytes());
        let capability = issue_capability(
            ProcessCapabilityId::new(id)?,
            &state.replay_guard,
            intent,
            expires,
            self.context.revision,
            self.context.epoch,
        );
        state.capability_counter = counter;
        Ok(capability)
    }

    pub fn approve(
        &self,
        intent: &ProcessIntentV1,
        expires: u64,
        approved: bool,
    ) -> Result<ProcessApprovalV1, ProcessContractError> {
        let state = self.authority.lock_for(&self.context)?;
        Ok(approve_bound(
            intent,
            approval_scope(intent),
            &state.replay_guard,
            &self.context,
            expires,
            approved,
        ))
    }

    pub fn validate(
        &self,
        intent: ProcessIntentV1,
        capability: Option<&ProcessCapabilityV1>,
        approval: Option<&ProcessApprovalV1>,
        now: u64,
    ) -> Result<ValidatedProcessIntentV1, ProcessContractError> {
        let mut state = self.authority.lock_for(&self.context)?;
        validate_authorization(
            intent,
            capability,
            approval,
            &self.context,
            &mut state.replay_guard,
            now,
        )
    }

    /// Checks one exact call without consuming its authorization material.
    pub fn preflight_authorization(
        &self,
        intent: &ProcessIntentV1,
        capability: Option<&ProcessCapabilityV1>,
        approval: Option<&ProcessApprovalV1>,
        now: u64,
    ) -> Result<(), ProcessContractError> {
        let state = self.authority.lock_for(&self.context)?;
        preflight_authorization(
            intent,
            capability,
            approval,
            &self.context,
            &state.replay_guard,
            now,
        )
    }
}
