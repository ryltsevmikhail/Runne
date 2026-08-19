use crate::{McpToolExecutionClass, fixture::FixtureCallResult};

use super::super::process_call::{
    ProcessEffectKey, audit_connection_digest, audit_invocation_digest,
};
use super::process_ledger::{ProcessEffectEvidence, ProcessRefundReason, ProcessUncertainReason};

/// Lifecycle phase recorded for a process-backed fixture dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureAuditProcessPhase {
    /// Resources were reserved before effect admission.
    Reserved,
    /// A pre-effect failure released the reservation.
    Refunded,
    /// An effect permit was admitted with its witness.
    Admitted,
    /// Complete terminal evidence settled the effect.
    Completed,
    /// The effect reached a state that cannot be safely resolved.
    Uncertain,
}

/// Reason associated with a process audit phase transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureAuditProcessReason {
    /// Authorization validation failed before admission.
    Authorization,
    /// Containment qualification failed before admission.
    Containment,
    /// Budget admission was denied.
    Budget,
    /// Gateway state was unavailable before an effect.
    GatewayUnavailable,
    /// Capability validation failed before admission.
    CapabilityPreflight,
    /// The process host denied the operation after admission.
    Denied,
    /// The executor reported a post-admission failure.
    Executor,
    /// The process host outcome was unavailable.
    Host,
    /// Terminal lifecycle evidence was insufficient.
    Lifecycle,
    /// Gateway cleanup could not be confirmed.
    Cleanup,
    /// The pending process call could not be recovered.
    Pending,
    /// Ledger state or evidence could not be verified.
    Ledger,
    /// Gateway state was ambiguous after admission.
    State,
}

/// Redacted audit record for a fixture dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureAuditRecord {
    execution_class: McpToolExecutionClass,
    result: Option<FixtureCallResult>,
    invocation_digest: [u8; 32],
    request_digest: [u8; 32],
    binding_digest: [u8; 32],
    intent_digest: Option<[u8; 32]>,
    issuer_digest: [u8; 32],
    definition_digest: [u8; 32],
    approval_digest: Option<[u8; 32]>,
    connection_digest: [u8; 32],
    generation: u64,
    tool_digest: [u8; 32],
    capability_digest: Option<[u8; 32]>,
    permit_digest: Option<[u8; 32]>,
    process_phase: Option<FixtureAuditProcessPhase>,
    process_reason: Option<FixtureAuditProcessReason>,
}

impl FixtureAuditRecord {
    /// Returns the dispatch execution class.
    pub fn execution_class(&self) -> McpToolExecutionClass {
        self.execution_class
    }
    /// Returns the terminal fixture result, when one was recorded.
    pub fn result(&self) -> Option<FixtureCallResult> {
        self.result
    }
    /// Returns the irreversible digest of the invocation identity.
    pub fn invocation_digest(&self) -> [u8; 32] {
        self.invocation_digest
    }
    /// Returns the canonical dispatch request digest.
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    /// Returns the authenticated dispatch binding digest.
    pub fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
    /// Returns the process intent digest for process-backed records.
    pub fn intent_digest(&self) -> Option<[u8; 32]> {
        self.intent_digest
    }
    /// Returns the discovery issuer digest.
    pub fn issuer_digest(&self) -> [u8; 32] {
        self.issuer_digest
    }
    /// Returns the published tool definition digest.
    pub fn definition_digest(&self) -> [u8; 32] {
        self.definition_digest
    }
    /// Returns the approval digest when the record has one.
    pub fn approval_digest(&self) -> Option<[u8; 32]> {
        self.approval_digest
    }
    /// Returns the irreversible connection identifier digest.
    pub fn connection_digest(&self) -> [u8; 32] {
        self.connection_digest
    }
    /// Returns the MCP generation associated with the dispatch.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Returns the selected tool name digest.
    pub fn tool_digest(&self) -> [u8; 32] {
        self.tool_digest
    }
    /// Returns the process capability digest when admission recorded one.
    pub fn capability_digest(&self) -> Option<[u8; 32]> {
        self.capability_digest
    }
    /// Returns the process permit digest when admission recorded one.
    pub fn permit_digest(&self) -> Option<[u8; 32]> {
        self.permit_digest
    }
    /// Returns the process lifecycle phase for process-backed records.
    pub fn process_phase(&self) -> Option<FixtureAuditProcessPhase> {
        self.process_phase
    }
    /// Returns the process lifecycle reason for process-backed records.
    pub fn process_reason(&self) -> Option<FixtureAuditProcessReason> {
        self.process_reason
    }

    pub(in crate::fixture) fn process(
        key: &ProcessEffectKey,
        phase: FixtureAuditProcessPhase,
        reason: Option<FixtureAuditProcessReason>,
        result: Option<FixtureCallResult>,
        evidence: Option<&ProcessEffectEvidence>,
    ) -> Self {
        let fields = key.audit_fields();
        let (capability, permit) = evidence
            .map(|value| (Some(value.capability_digest), Some(value.permit_digest)))
            .unwrap_or((None, None));
        Self {
            execution_class: McpToolExecutionClass::ProcessBacked,
            result,
            invocation_digest: audit_invocation_digest(key.invocation_id()),
            request_digest: fields.request_digest(),
            binding_digest: fields.binding_digest(),
            intent_digest: Some(fields.intent_digest()),
            issuer_digest: fields.issuer_digest(),
            definition_digest: fields.definition_digest(),
            approval_digest: Some(fields.approval_digest()),
            connection_digest: audit_connection_digest(key.connection_id()),
            generation: fields.generation(),
            tool_digest: fields.tool_digest(),
            capability_digest: capability,
            permit_digest: permit,
            process_phase: Some(phase),
            process_reason: reason,
        }
    }

    pub(in crate::fixture) fn refund_reason(
        reason: ProcessRefundReason,
    ) -> FixtureAuditProcessReason {
        match reason {
            ProcessRefundReason::Authorization => FixtureAuditProcessReason::Authorization,
            ProcessRefundReason::Containment => FixtureAuditProcessReason::Containment,
            #[cfg(test)]
            ProcessRefundReason::Budget => FixtureAuditProcessReason::Budget,
            ProcessRefundReason::GatewayUnavailable => {
                FixtureAuditProcessReason::GatewayUnavailable
            }
            ProcessRefundReason::CapabilityPreflight => {
                FixtureAuditProcessReason::CapabilityPreflight
            }
        }
    }

    pub(in crate::fixture) fn uncertain_reason(
        reason: ProcessUncertainReason,
    ) -> FixtureAuditProcessReason {
        match reason {
            ProcessUncertainReason::Denied => FixtureAuditProcessReason::Denied,
            ProcessUncertainReason::Executor => FixtureAuditProcessReason::Executor,
            ProcessUncertainReason::Host => FixtureAuditProcessReason::Host,
            ProcessUncertainReason::Lifecycle => FixtureAuditProcessReason::Lifecycle,
            ProcessUncertainReason::Cleanup => FixtureAuditProcessReason::Cleanup,
            ProcessUncertainReason::Pending => FixtureAuditProcessReason::Pending,
            ProcessUncertainReason::Ledger => FixtureAuditProcessReason::Ledger,
            ProcessUncertainReason::State => FixtureAuditProcessReason::State,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::fixture) fn protocol(
        invocation: &str,
        request_digest: [u8; 32],
        binding_digest: [u8; 32],
        issuer_digest: [u8; 32],
        definition_digest: [u8; 32],
        approval_digest: [u8; 32],
        connection: &str,
        generation: u64,
        tool: &str,
        result: FixtureCallResult,
    ) -> Self {
        Self {
            execution_class: McpToolExecutionClass::ProtocolOnly,
            result: Some(result),
            invocation_digest: audit_invocation_digest(invocation),
            request_digest,
            binding_digest,
            intent_digest: None,
            issuer_digest,
            definition_digest,
            approval_digest: Some(approval_digest),
            connection_digest: audit_connection_digest(connection),
            generation,
            tool_digest: super::super::model::digest(&[tool.as_bytes()]),
            capability_digest: None,
            permit_digest: None,
            process_phase: None,
            process_reason: None,
        }
    }
}
