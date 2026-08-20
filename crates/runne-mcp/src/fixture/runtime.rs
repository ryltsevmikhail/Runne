use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

#[cfg(test)]
use runne_tools::{ProcessApprovalV1, ProcessCapabilityV1, ProcessIntentV1};
use runne_tools::{
    ProcessAuthorizationAuthorityV1, ProcessContractHostV1, SandboxQualificationProbe,
    ToolExecutionHandle, ToolOutputBounds,
};
use serde_json::Value;

use crate::{
    FixtureMcpFailure, FixtureMcpMode, McpConnectionId, McpDispatchBinding, McpGenerationAuthority,
    McpServerKind, McpToolDescriptor, McpToolDispatchCapability, McpToolExecutionClass,
    McpToolGateway, PublishedMcpTools, publish_mcp_tools,
};

use self::process_ledger::ProcessLedgerEntry;
use super::model::{
    FixtureApprovalPolicy, FixtureCallResult, FixtureIdentity, FixtureInitialize, FixtureLimits,
    FixtureScript, FixtureStepOutcome, FixtureTool,
};
use super::process::FixtureProcessComposition;
use super::process_call::{ProcessDispatchPayload, ProcessEffectKey};
use super::process_gateway::McpProcessToolGateway;
use super::transport::{FixtureAdmission, FixtureClient};

static FIXTURE_ISSUER_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// In-process deterministic fixture runtime; it owns no I/O, process, or task handles.
pub struct FixtureMcpRuntime {
    mode: FixtureMcpMode,
    identity: FixtureIdentity,
    tools: Vec<FixtureTool>,
    script: FixtureScript,
    allowlist: BTreeSet<String>,
    limits: FixtureLimits,
    policy: FixtureApprovalPolicy,
    definition_digest: [u8; 32],
    issuer_digest: [u8; 32],
    state: Arc<Mutex<FixtureState>>,
    gateway: Option<McpToolGateway<FixtureAdmission, FixtureClient>>,
    process_composition: Option<FixtureProcessComposition>,
    process_gateway: Option<McpProcessToolGateway>,
    process_generation: Option<u64>,
}

pub(super) struct FixtureState {
    pub(super) active: Option<FixtureInitialize>,
    reconnect_required: Option<ReconnectRequirement>,
    reconnect_identity: Option<FixtureInitialize>,
    tick: u64,
    next_step: usize,
    remaining: u64,
    effects: BTreeMap<EffectKey, FixtureCallResult>,
    process_ledger: BTreeMap<String, ProcessLedgerEntry>,
    audit: Vec<FixtureAuditRecord>,
    pub(super) dispatches: u64,
    pub(super) selected_outcomes: BTreeMap<String, FixtureStepOutcome>,
    pub(super) protocol_reservations: BTreeMap<String, FixtureProtocolReservation>,
}

pub(super) struct FixtureProtocolReservation {
    pub(super) request_digest: [u8; 32],
    pub(super) permit_id: String,
    pub(super) handle: ToolExecutionHandle,
    pub(super) connection_id: String,
    pub(super) generation: u64,
    pub(super) terminal_digest: Option<[u8; 32]>,
    pub(super) settled: bool,
}

enum ReconnectRequirement {
    Exact(McpConnectionId, u64),
    Fresh(McpConnectionId, u64),
}

/// Immutable authenticated discovery publication.
pub struct FixturePublication {
    pub(super) published: Arc<PublishedMcpTools>,
    pub(super) binding: McpDispatchBinding,
    pub(super) tools: BTreeMap<String, FixtureTool>,
    pub(super) state: Arc<Mutex<FixtureState>>,
    pub(super) limits: FixtureLimits,
    pub(super) policy: FixtureApprovalPolicy,
    pub(super) issuer_digest: [u8; 32],
    pub(super) definition_digest: [u8; 32],
}

/// Opaque single-use fixture capability with an exact approval binding.
pub struct FixtureCallCapability {
    pub(super) capability: Option<McpToolDispatchCapability>,
    pub(super) execution_class: McpToolExecutionClass,
    pub(super) process_key: Option<ProcessEffectKey>,
    pub(super) process_payload: Option<ProcessDispatchPayload>,
    #[cfg(test)]
    pub(super) process_payload_take_count: usize,
    pub(super) invocation_id: String,
    pub(super) approval_digest: [u8; 32],
    pub(super) connection_id: String,
    pub(super) generation: u64,
    pub(super) expires_at: u64,
    pub(super) request_digest: [u8; 32],
    pub(super) issuer_digest: [u8; 32],
    pub(super) definition_digest: [u8; 32],
    pub(super) tool_name: String,
    pub(super) effect_key: EffectKey,
}

impl FixtureCallCapability {
    pub(in crate::fixture) const fn execution_class(&self) -> McpToolExecutionClass {
        self.execution_class
    }
    pub(in crate::fixture) fn process_key(&self) -> Option<&ProcessEffectKey> {
        self.process_key.as_ref()
    }
    pub(in crate::fixture) fn take_process_payload(&mut self) -> Option<ProcessDispatchPayload> {
        #[cfg(test)]
        {
            self.process_payload_take_count += 1;
        }
        self.process_payload.take()
    }
    pub(in crate::fixture) fn restore_process_payload(&mut self, payload: ProcessDispatchPayload) {
        assert!(
            self.process_payload.is_none(),
            "process payload already present"
        );
        self.process_payload = Some(payload);
    }
    #[cfg(test)]
    pub(in crate::fixture) const fn process_payload_take_count_for_test(&self) -> usize {
        self.process_payload_take_count
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EffectKey {
    invocation_id: String,
    request_digest: [u8; 32],
    binding_digest: [u8; 32],
    connection_id: String,
    generation: u64,
    tool_name: String,
}

impl EffectKey {
    pub(super) fn new(
        invocation_id: String,
        request_digest: [u8; 32],
        binding_digest: [u8; 32],
        connection_id: String,
        generation: u64,
        tool_name: String,
    ) -> Self {
        Self {
            invocation_id,
            request_digest,
            binding_digest,
            connection_id,
            generation,
            tool_name,
        }
    }
}

/// Explicit typed approval for one exact fixture capability.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FixtureApproval([u8; 32]);

/// Fixture-local approval authority, separate from dispatch capability issuance.
#[derive(Clone, Copy)]
pub struct FixtureApprovalAuthority {
    issuer_digest: [u8; 32],
}

/// Process capability and approval issuer backed by one shared authority.
#[derive(Clone)]
pub(in crate::fixture) struct FixtureProcessApprovalAuthority {
    authority: ProcessAuthorizationAuthorityV1,
}

impl FixtureProcessApprovalAuthority {
    /// Takes ownership of the explicit process authorization authority.
    #[cfg(test)]
    #[must_use]
    pub fn new(authority: ProcessAuthorizationAuthorityV1) -> Self {
        Self { authority }
    }

    /// Issues an exact process capability through a fresh bound child.
    #[cfg(test)]
    pub fn issue_capability(
        &self,
        intent: &ProcessIntentV1,
        expires_at: u64,
    ) -> Result<ProcessCapabilityV1, FixtureMcpFailure> {
        self.authority
            .bind_call(intent.lifecycle_binding())?
            .issue_capability(intent, expires_at)
            .map_err(Into::into)
    }

    /// Issues an exact process approval through a fresh bound child.
    #[cfg(test)]
    pub fn approve(
        &self,
        intent: &ProcessIntentV1,
        expires_at: u64,
        approved: bool,
    ) -> Result<ProcessApprovalV1, FixtureMcpFailure> {
        Ok(self
            .authority
            .bind_call(intent.lifecycle_binding())?
            .approve(intent, expires_at, approved)?)
    }

    pub(super) fn prepare_authorization_advance(
        &self,
    ) -> Result<runne_tools::ProcessAuthorizationAdvanceV1<'_>, runne_tools::ProcessContractError>
    {
        self.authority.prepare_advance()
    }

    pub(super) fn compose_gateway(
        &self,
        host: ProcessContractHostV1,
        probe: Arc<dyn SandboxQualificationProbe>,
        generation: Arc<McpGenerationAuthority>,
        ledger: Arc<process_ledger::FixtureProcessLedgerPort>,
        bounds: ToolOutputBounds,
    ) -> McpProcessToolGateway {
        McpProcessToolGateway::new(
            self.authority.clone(),
            host,
            probe,
            generation,
            ledger,
            bounds,
        )
    }
}

impl FixtureApprovalAuthority {
    /// Approves exactly the immutable capability supplied by the fixture caller.
    pub fn approve(
        &self,
        capability: &FixtureCallCapability,
    ) -> Result<FixtureApproval, FixtureMcpFailure> {
        if self.issuer_digest != capability.issuer_digest {
            return Err(FixtureMcpFailure::ApprovalMismatch);
        }
        Ok(FixtureApproval(capability.approval_digest))
    }
}

include!("runtime/lifecycle.rs");
#[path = "runtime/process_audit.rs"]
mod process_audit;
#[path = "runtime/process_ledger.rs"]
pub(in crate::fixture) mod process_ledger;
pub use process_audit::{FixtureAuditProcessPhase, FixtureAuditProcessReason, FixtureAuditRecord};
include!("runtime/process_activation.rs");
mod process_dispatch;
include!("runtime/dispatch.rs");
#[cfg(test)]
include!("runtime/source_pin_tests.rs");
