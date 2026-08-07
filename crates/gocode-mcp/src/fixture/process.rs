use std::sync::Arc;

use gocode_tools::{
    ProcessApprovalV1, ProcessAuthorizationAdvanceV1, ProcessAuthorizationAuthorityV1,
    ProcessCapabilityV1, ProcessContractError, ProcessContractHostV1, ProcessIntentV1,
    SandboxQualificationProbe, ToolExecutionHandle, ToolOutputBounds, production_sandbox_probe,
};

use gocode_tools::{
    AuthorityId, CapabilityGrantId, PrincipalId, ProcessIdentityBindingV1, SandboxId,
};

use crate::discovery::derive_process_lifecycle_binding;
use crate::{McpDispatchBinding, McpInvocationId};
use crate::{McpGenerationAuthority, McpToolDispatchCapability};

use super::{FixtureProcessApprovalAuthority, McpProcessToolGateway};

/// Opaque production process composition retained across fixture reconnects.
pub struct FixtureProcessComposition {
    authority: FixtureProcessApprovalAuthority,
    host: Option<ProcessContractHostV1>,
    probe: Arc<dyn SandboxQualificationProbe>,
    host_compositions: u64,
}

/// Safe metadata about a sealed fixture process composition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureProcessCompositionMetadata {
    host_compositions: u64,
    generation: Option<u64>,
}

impl FixtureProcessCompositionMetadata {
    /// Returns how many times the exclusive host was composed into a gateway.
    #[must_use]
    pub const fn host_compositions(self) -> u64 {
        self.host_compositions
    }

    /// Returns the generation bound to the composed process gateway.
    #[must_use]
    pub const fn generation(self) -> Option<u64> {
        self.generation
    }
}

impl FixtureProcessComposition {
    /// Composes the only production probe with an explicit shared authority and host.
    #[must_use]
    pub fn new(authority: ProcessAuthorizationAuthorityV1, host: ProcessContractHostV1) -> Self {
        Self::with_probe(authority, host, Arc::new(production_sandbox_probe()))
    }

    /// Returns safe metadata without exposing the host, probe, or replay boundary.
    #[must_use]
    pub const fn metadata(&self, generation: Option<u64>) -> FixtureProcessCompositionMetadata {
        FixtureProcessCompositionMetadata {
            host_compositions: self.host_compositions,
            generation,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_probe(
        authority: ProcessAuthorizationAuthorityV1,
        host: ProcessContractHostV1,
        probe: Arc<dyn SandboxQualificationProbe>,
    ) -> Self {
        Self::with_probe(authority, host, probe)
    }

    fn with_probe(
        authority: ProcessAuthorizationAuthorityV1,
        host: ProcessContractHostV1,
        probe: Arc<dyn SandboxQualificationProbe>,
    ) -> Self {
        Self {
            authority: FixtureProcessApprovalAuthority::new(authority),
            host: Some(host),
            probe,
            host_compositions: 0,
        }
    }

    pub(super) fn authority(&self) -> FixtureProcessApprovalAuthority {
        self.authority.clone()
    }

    pub(super) fn prepare_authorization_advance(
        &self,
    ) -> Result<ProcessAuthorizationAdvanceV1<'_>, ProcessContractError> {
        self.authority.prepare_authorization_advance()
    }

    pub(super) fn compose_gateway(
        &mut self,
        generation: Arc<McpGenerationAuthority>,
        bounds: ToolOutputBounds,
    ) -> Option<McpProcessToolGateway> {
        let host = self.host.take()?;
        self.host_compositions = self.host_compositions.saturating_add(1);
        Some(
            self.authority
                .compose_gateway(host, Arc::clone(&self.probe), generation, bounds),
        )
    }
}

/// Opaque process authorization material for one exact MCP process call.
pub struct McpProcessCall {
    pub(super) capability: McpToolDispatchCapability,
    pub(super) intent: ProcessIntentV1,
    pub(super) process_capability: Option<ProcessCapabilityV1>,
    pub(super) approval: Option<ProcessApprovalV1>,
    pub(super) now: u64,
}

/// Metadata-only terminal replay state for one exact process invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProcessTerminalRecord {
    /// The sealed host completed and the process gateway closed the exact handle.
    Completed {
        digest: [u8; 32],
        handle: ToolExecutionHandle,
    },
    /// The effect cannot be safely replayed after admission.
    Uncertain { digest: [u8; 32] },
}

/// Exact replay resolution without process output or raw host material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProcessTerminalReplay {
    /// The exact completed handle may be returned without redispatch.
    Completed(ToolExecutionHandle),
    /// The exact effect remains uncertain.
    Uncertain,
    /// The invocation identifier was reused with another digest.
    DigestConflict,
}

impl ProcessTerminalRecord {
    pub(super) const fn completed(digest: [u8; 32], handle: ToolExecutionHandle) -> Self {
        Self::Completed { digest, handle }
    }

    pub(super) const fn uncertain(digest: [u8; 32]) -> Self {
        Self::Uncertain { digest }
    }

    pub(super) fn replay(&self, digest: [u8; 32]) -> ProcessTerminalReplay {
        match self {
            Self::Completed {
                digest: stored,
                handle,
            } if *stored == digest => ProcessTerminalReplay::Completed(handle.clone()),
            Self::Uncertain { digest: stored } if *stored == digest => {
                ProcessTerminalReplay::Uncertain
            }
            _ => ProcessTerminalReplay::DigestConflict,
        }
    }
}

impl McpProcessCall {
    /// Binds all process authorization material before dispatch.
    #[must_use]
    #[rustfmt::skip]
    pub fn new(capability: McpToolDispatchCapability, intent: ProcessIntentV1, process_capability: ProcessCapabilityV1, approval: ProcessApprovalV1, now: u64) -> Self { Self { capability, intent, process_capability: Some(process_capability), approval: Some(approval), now } }

    /// Binds a call whose process approval is deliberately absent.
    #[must_use]
    #[rustfmt::skip]
    pub fn without_process_approval(capability: McpToolDispatchCapability, intent: ProcessIntentV1, process_capability: ProcessCapabilityV1, now: u64) -> Self { Self { capability, intent, process_capability: Some(process_capability), approval: None, now } }

    #[cfg(test)]
    pub(crate) fn without_process_intent_digest_for_test(mut self) -> Self {
        self.capability = self.capability.without_process_intent_digest_for_test();
        self
    }

    #[cfg(test)]
    pub(crate) fn with_invocation_id_for_test(mut self, invocation_id: &str) -> Self {
        self.capability = self.capability.with_invocation_id_for_test(invocation_id);
        self
    }
}

/// Derives the process identity that is exact for one MCP dispatch lifecycle.
#[must_use]
pub fn derive_process_identity_binding(
    binding: &McpDispatchBinding,
    invocation: &McpInvocationId,
    principal: PrincipalId,
    authority: AuthorityId,
    accounting: CapabilityGrantId,
    sandbox: SandboxId,
) -> ProcessIdentityBindingV1 {
    let lifecycle = derive_process_lifecycle_binding(binding, invocation);
    ProcessIdentityBindingV1::new(
        principal,
        authority,
        lifecycle.owner().clone(),
        lifecycle.attempt().clone(),
        lifecycle.session().clone(),
        lifecycle.generation().clone(),
        accounting,
        sandbox,
        lifecycle.tree_handle().clone(),
    )
}

#[cfg(test)]
mod tests {
    use gocode_tools::ToolExecutionHandle;

    use super::{ProcessTerminalRecord, ProcessTerminalReplay};

    #[test]
    fn terminal_record_replays_only_the_exact_completed_or_uncertain_digest() {
        let digest = [1; 32];
        let handle = ToolExecutionHandle {
            execution_id: "completed".into(),
        };
        let completed = ProcessTerminalRecord::completed(digest, handle.clone());

        assert_eq!(
            completed.replay(digest),
            ProcessTerminalReplay::Completed(handle)
        );
        assert_eq!(
            completed.replay([2; 32]),
            ProcessTerminalReplay::DigestConflict
        );
        assert_eq!(
            ProcessTerminalRecord::uncertain(digest).replay(digest),
            ProcessTerminalReplay::Uncertain
        );
    }
}
