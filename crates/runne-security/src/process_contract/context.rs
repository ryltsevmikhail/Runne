//! Trusted current-context verification separated from authorization replay state.

use runne_platform_ports::process::{VerifiedCwdV1, VerifiedExecutableV1};

use super::{
    AllowedRootId, ApproverId, ExecutablePolicyId, ProcessContractError, ProcessIdentityBindingV1,
    ProcessIntentV1,
};

#[derive(Clone)]
pub(crate) struct CurrentProcessContextV1 {
    executable: VerifiedExecutableV1,
    policy: ExecutablePolicyId,
    cwd: VerifiedCwdV1,
    root: AllowedRootId,
    binding: ProcessIdentityBindingV1,
    pub(crate) approver: ApproverId,
    pub(crate) revision: u64,
    pub(crate) epoch: u64,
}

impl CurrentProcessContextV1 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        executable: VerifiedExecutableV1,
        policy: ExecutablePolicyId,
        cwd: VerifiedCwdV1,
        root: AllowedRootId,
        binding: ProcessIdentityBindingV1,
        approver: ApproverId,
        revision: u64,
        epoch: u64,
    ) -> Self {
        Self {
            executable,
            policy,
            cwd,
            root,
            binding,
            approver,
            revision,
            epoch,
        }
    }
}

#[cfg(test)]
pub(crate) fn current_context(
    intent: &ProcessIntentV1,
    approver: ApproverId,
    revision: u64,
    epoch: u64,
) -> CurrentProcessContextV1 {
    CurrentProcessContextV1 {
        executable: intent.executable().clone(),
        policy: intent.executable_policy().clone(),
        cwd: intent.cwd().clone(),
        root: intent.allowed_root().clone(),
        binding: intent.binding().clone(),
        approver,
        revision,
        epoch,
    }
}

pub(crate) fn validate_current_context(
    current: &CurrentProcessContextV1,
    intent: &ProcessIntentV1,
) -> Result<(), ProcessContractError> {
    if current.binding != *intent.binding() {
        return Err(ProcessContractError::CapabilityInvalid);
    }
    if current.executable != *intent.executable() || current.policy != *intent.executable_policy() {
        return Err(ProcessContractError::ExecutableVerificationFailed);
    }
    if current.cwd != *intent.cwd() || current.root != *intent.allowed_root() {
        return Err(ProcessContractError::CwdVerificationFailed);
    }
    Ok(())
}
