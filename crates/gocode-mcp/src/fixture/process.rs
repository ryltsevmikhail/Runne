use std::sync::{Arc, Mutex};

use gocode_tools::{
    ProcessAuthorizationAdvanceV1, ProcessContractError, ProcessContractHostV1,
    SandboxQualificationProbe, ToolOutputBounds,
};

#[cfg(test)]
use gocode_tools::{
    AuthorityId, CapabilityGrantId, PrincipalId, ProcessAuthorizationAuthorityV1,
    ProcessIdentityBindingV1, SandboxId, production_sandbox_probe,
};

use crate::McpGenerationAuthority;
#[cfg(test)]
use crate::discovery::derive_process_lifecycle_binding;
#[cfg(test)]
use crate::{McpDispatchBinding, McpInvocationId};

use super::process_gateway::McpProcessToolGateway;
use super::runtime::FixtureProcessApprovalAuthority;

/// Opaque production process composition retained across fixture reconnects.
pub(in crate::fixture) struct FixtureProcessComposition {
    authority: FixtureProcessApprovalAuthority,
    host: Mutex<Option<ProcessContractHostV1>>,
    probe: Arc<dyn SandboxQualificationProbe>,
    #[cfg(test)]
    host_compositions: u64,
}

/// Safe test metadata about a sealed fixture process composition.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fixture) struct FixtureProcessCompositionMetadata {
    host_compositions: u64,
    generation: Option<u64>,
}

#[cfg(test)]
impl FixtureProcessCompositionMetadata {
    /// Returns how many times the exclusive host was composed into a gateway.
    #[must_use]
    pub(in crate::fixture) const fn host_compositions(self) -> u64 {
        self.host_compositions
    }

    /// Returns the generation bound to the composed process gateway.
    #[must_use]
    pub(in crate::fixture) const fn generation(self) -> Option<u64> {
        self.generation
    }
}

impl FixtureProcessComposition {
    /// Composes the only production probe with an explicit shared authority and host.
    #[cfg(test)]
    #[must_use]
    pub(in crate::fixture) fn new(
        authority: ProcessAuthorizationAuthorityV1,
        host: ProcessContractHostV1,
    ) -> Self {
        Self::with_probe(authority, host, Arc::new(production_sandbox_probe()))
    }

    #[cfg(test)]
    #[must_use]
    pub(in crate::fixture) const fn metadata(
        &self,
        generation: Option<u64>,
    ) -> FixtureProcessCompositionMetadata {
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

    #[cfg(test)]
    fn with_probe(
        authority: ProcessAuthorizationAuthorityV1,
        host: ProcessContractHostV1,
        probe: Arc<dyn SandboxQualificationProbe>,
    ) -> Self {
        Self {
            authority: FixtureProcessApprovalAuthority::new(authority),
            host: Mutex::new(Some(host)),
            probe,
            #[cfg(test)]
            host_compositions: 0,
        }
    }

    #[cfg(test)]
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
        ledger: Arc<super::runtime::process_ledger::FixtureProcessLedgerPort>,
        bounds: ToolOutputBounds,
    ) -> Option<McpProcessToolGateway> {
        let host = self.host.lock().ok()?.take()?;
        #[cfg(test)]
        let () = {
            self.host_compositions = self.host_compositions.saturating_add(1);
        };
        Some(self.authority.compose_gateway(
            host,
            Arc::clone(&self.probe),
            generation,
            ledger,
            bounds,
        ))
    }
}

/// Derives the process identity that is exact for one MCP dispatch lifecycle.
#[must_use]
#[cfg(test)]
pub(in crate::fixture) fn derive_process_identity_binding(
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
