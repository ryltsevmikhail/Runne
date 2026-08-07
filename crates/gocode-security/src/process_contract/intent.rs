//! Immutable process intent with marker-safe input representations.

use core::fmt;

use gocode_platform_ports::process::{
    HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1, ProcessLifecycleBindingV1,
    ProcessOwnerIdV1, ProcessSessionIdV1, VerifiedCwdV1, VerifiedExecutableV1,
};

use super::{
    AllowedRootId, ApprovalId, AuthorityId, CapabilityGrantId, ExecutablePolicyId, PrincipalId,
    ProcessContractError, SandboxId, digest::digest_intent,
};

mod input;

pub use input::{
    BoundedArgvV1, ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, StdinPolicyV1,
};
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use input::{EnvironmentClassificationV1, ProcessEnvironmentGrantV1};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIoBoundsV1 {
    pub(super) stdout: u64,
    pub(super) stderr: u64,
    pub(super) combined: u64,
    pub(super) timeout: u64,
    pub(super) cancel: bool,
}

impl ProcessIoBoundsV1 {
    pub fn new(
        stdout: u64,
        stderr: u64,
        combined: u64,
        timeout: u64,
        cancel: bool,
    ) -> Result<Self, ProcessContractError> {
        let Some(total) = stdout.checked_add(stderr) else {
            return Err(ProcessContractError::InputBoundsExceeded);
        };
        if combined == 0 || combined > total || timeout == 0 {
            return Err(ProcessContractError::InputBoundsExceeded);
        }
        Ok(Self {
            stdout,
            stderr,
            combined,
            timeout,
            cancel,
        })
    }

    /// Returns the validated monotonic timeout budget in ticks.
    #[must_use]
    pub const fn timeout_ticks(&self) -> u64 {
        self.timeout
    }

    /// Returns whether the validated intent permits explicit cancellation.
    #[must_use]
    pub const fn cancellation_permitted(&self) -> bool {
        self.cancel
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentityBindingV1 {
    pub(super) principal: PrincipalId,
    pub(super) authority: AuthorityId,
    pub(super) owner: ProcessOwnerIdV1,
    pub(super) attempt: ProcessAttemptIdV1,
    pub(super) session: ProcessSessionIdV1,
    pub(super) generation: ProcessGenerationIdV1,
    pub(super) accounting: CapabilityGrantId,
    pub(super) sandbox: SandboxId,
    pub(super) tree: HeldProcessTreeHandleV1,
}

impl ProcessIdentityBindingV1 {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        principal: PrincipalId,
        authority: AuthorityId,
        owner: ProcessOwnerIdV1,
        attempt: ProcessAttemptIdV1,
        session: ProcessSessionIdV1,
        generation: ProcessGenerationIdV1,
        accounting: CapabilityGrantId,
        sandbox: SandboxId,
        tree: HeldProcessTreeHandleV1,
    ) -> Self {
        Self {
            principal,
            authority,
            owner,
            attempt,
            session,
            generation,
            accounting,
            sandbox,
            tree,
        }
    }

    /// Returns the opaque owner identity for exact lifecycle binding.
    #[must_use]
    pub const fn owner(&self) -> &ProcessOwnerIdV1 {
        &self.owner
    }

    /// Returns the opaque attempt identity for exact lifecycle binding.
    #[must_use]
    pub const fn attempt(&self) -> &ProcessAttemptIdV1 {
        &self.attempt
    }

    /// Returns the opaque session identity for exact lifecycle binding.
    #[must_use]
    pub const fn session(&self) -> &ProcessSessionIdV1 {
        &self.session
    }

    /// Returns the opaque generation identity for exact lifecycle binding.
    #[must_use]
    pub const fn generation(&self) -> &ProcessGenerationIdV1 {
        &self.generation
    }

    /// Returns the held opaque process-tree handle for exact lifecycle binding.
    #[must_use]
    pub const fn tree(&self) -> &HeldProcessTreeHandleV1 {
        &self.tree
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIntentDigestV1(pub(crate) [u8; 32]);
impl ProcessIntentDigestV1 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Immutable, exact effect input. `Debug` never serializes raw input values.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessIntentV1 {
    approval: ApprovalId,
    executable: VerifiedExecutableV1,
    executable_policy: ExecutablePolicyId,
    cwd: VerifiedCwdV1,
    allowed_root: AllowedRootId,
    argv: BoundedArgvV1,
    environment: ExplicitEnvironmentV1,
    stdin: StdinPolicyV1,
    bounds: ProcessIoBoundsV1,
    binding: ProcessIdentityBindingV1,
    digest: ProcessIntentDigestV1,
}

impl ProcessIntentV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        approval: ApprovalId,
        executable: VerifiedExecutableV1,
        executable_policy: ExecutablePolicyId,
        cwd: VerifiedCwdV1,
        allowed_root: AllowedRootId,
        argv: BoundedArgvV1,
        environment: ExplicitEnvironmentV1,
        stdin: StdinPolicyV1,
        bounds: ProcessIoBoundsV1,
        binding: ProcessIdentityBindingV1,
    ) -> Result<Self, ProcessContractError> {
        let mut value = Self {
            approval,
            executable,
            executable_policy,
            cwd,
            allowed_root,
            argv,
            environment,
            stdin,
            bounds,
            binding,
            digest: ProcessIntentDigestV1([0; 32]),
        };
        value.digest = digest_intent(&value)?;
        Ok(value)
    }

    #[must_use]
    pub const fn digest(&self) -> ProcessIntentDigestV1 {
        self.digest
    }

    /// Projects the exact opaque lifecycle binding from this immutable intent.
    #[must_use]
    pub fn lifecycle_binding(&self) -> ProcessLifecycleBindingV1 {
        ProcessLifecycleBindingV1::new(
            self.binding.owner().clone(),
            self.binding.attempt().clone(),
            self.binding.session().clone(),
            self.binding.generation().clone(),
            self.binding.tree().clone(),
        )
    }

    pub(crate) fn approval(&self) -> &ApprovalId {
        &self.approval
    }
    pub(crate) fn executable(&self) -> &VerifiedExecutableV1 {
        &self.executable
    }
    pub(crate) fn executable_policy(&self) -> &ExecutablePolicyId {
        &self.executable_policy
    }
    pub(crate) fn cwd(&self) -> &VerifiedCwdV1 {
        &self.cwd
    }
    pub(crate) fn allowed_root(&self) -> &AllowedRootId {
        &self.allowed_root
    }
    pub(crate) fn argv(&self) -> &BoundedArgvV1 {
        &self.argv
    }
    pub(crate) fn environment(&self) -> &ExplicitEnvironmentV1 {
        &self.environment
    }
    pub(crate) fn bounds(&self) -> &ProcessIoBoundsV1 {
        &self.bounds
    }
    pub(crate) fn binding(&self) -> &ProcessIdentityBindingV1 {
        &self.binding
    }
}

impl fmt::Debug for ProcessIntentV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProcessIntentV1(redacted,digest={})",
            hex::encode(self.digest.0)
        )
    }
}

impl fmt::Debug for super::ProcessCapabilityV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessCapabilityV1(redacted)")
    }
}

impl fmt::Debug for super::ProcessApprovalV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessApprovalV1(redacted)")
    }
}

impl fmt::Debug for super::ValidatedProcessIntentV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedProcessIntentV1(redacted)")
    }
}
