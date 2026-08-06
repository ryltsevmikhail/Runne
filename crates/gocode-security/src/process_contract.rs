//! Immutable, fail-closed contracts for a future process effect.

use core::fmt;

use sha2::{Digest, Sha256};

mod authorization;
mod context;
mod digest;
mod error;
mod ids;
mod intent;

pub use authorization::{ProcessApprovalV1, ProcessCapabilityV1, ValidatedProcessIntentV1};
pub use error::ProcessContractError;
pub use ids::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, CapabilityGrantId, ExecutablePolicyId,
    PrincipalId, ProcessCapabilityId, SandboxId,
};
pub use intent::{
    BoundedArgvV1, ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, ProcessIdentityBindingV1,
    ProcessIntentDigestV1, ProcessIntentV1, ProcessIoBoundsV1, StdinPolicyV1,
};

/// Immutable output limits extracted from a validated sealed process witness.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ValidatedProcessOutputLimitsV1 {
    stdin: u64,
    stdout: u64,
    stderr: u64,
    combined: u64,
}

impl ValidatedProcessOutputLimitsV1 {
    /// Returns the sealed stdin limit.
    #[must_use]
    pub const fn stdin(&self) -> u64 {
        self.stdin
    }
    /// Returns the sealed stdout limit.
    #[must_use]
    pub const fn stdout(&self) -> u64 {
        self.stdout
    }
    /// Returns the sealed stderr limit.
    #[must_use]
    pub const fn stderr(&self) -> u64 {
        self.stderr
    }
    /// Returns the sealed combined-output limit.
    #[must_use]
    pub const fn combined(&self) -> u64 {
        self.combined
    }
}

impl fmt::Debug for ValidatedProcessOutputLimitsV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedProcessOutputLimitsV1(redacted)")
    }
}

/// Opaque fixed-width recipient label derived from validated principal and owner identities.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProcessOutputCallerLabelV1([u8; 16]);

impl ProcessOutputCallerLabelV1 {
    /// Returns the safe fixed-width routing label without exposing source identities.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for ProcessOutputCallerLabelV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessOutputCallerLabelV1(redacted)")
    }
}

impl ValidatedProcessIntentV1 {
    /// Returns the exact digest validated by the security boundary.
    #[must_use]
    pub const fn digest(&self) -> ProcessIntentDigestV1 {
        self.intent().digest()
    }

    /// Returns the verified executable identity for adapter revalidation.
    #[must_use]
    pub fn executable(&self) -> &gocode_platform_ports::process::VerifiedExecutableV1 {
        self.intent().executable()
    }

    /// Returns the verified working-directory identity for adapter revalidation.
    #[must_use]
    pub fn cwd(&self) -> &gocode_platform_ports::process::VerifiedCwdV1 {
        self.intent().cwd()
    }

    /// Returns the exact opaque lifecycle binding; it never exposes an identifier-only control.
    #[must_use]
    pub fn lifecycle_binding(&self) -> gocode_platform_ports::process::ProcessLifecycleBindingV1 {
        let binding = self.intent().binding();
        gocode_platform_ports::process::ProcessLifecycleBindingV1::new(
            binding.owner().clone(),
            binding.attempt().clone(),
            binding.session().clone(),
            binding.generation().clone(),
            binding.tree().clone(),
        )
    }

    /// Returns the validated monotonic timeout budget in ticks.
    #[must_use]
    pub fn timeout_ticks(&self) -> u64 {
        self.intent().bounds().timeout_ticks()
    }

    /// Returns whether this sealed intent permits cancellation control.
    #[must_use]
    pub fn cancellation_permitted(&self) -> bool {
        self.intent().bounds().cancellation_permitted()
    }

    /// Returns output limits derived only from the validated sealed witness.
    #[must_use]
    pub fn output_limits(&self) -> ValidatedProcessOutputLimitsV1 {
        let bounds = self.intent().bounds();
        ValidatedProcessOutputLimitsV1 {
            stdin: 0,
            stdout: bounds.stdout,
            stderr: bounds.stderr,
            combined: bounds.combined,
        }
    }

    /// Returns the fixed-width caller label derived from the validated principal and owner.
    #[must_use]
    pub fn output_caller_label(&self) -> ProcessOutputCallerLabelV1 {
        let binding = self.intent().binding();
        let mut digest = Sha256::new();
        digest.update(binding.principal.bytes());
        digest.update(binding.owner.as_bytes());
        let digest: [u8; 32] = digest.finalize().into();
        let mut label = [0; 16];
        label.copy_from_slice(&digest[..16]);
        ProcessOutputCallerLabelV1(label)
    }
}

#[cfg(test)]
mod tests;
