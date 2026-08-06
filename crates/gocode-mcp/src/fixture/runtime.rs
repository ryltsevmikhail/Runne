use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use gocode_tools::{ToolExecutionHandle, ToolOutputBounds};
use serde_json::Value;

use crate::{
    FixtureMcpFailure, FixtureMcpMode, McpConnectionId, McpDispatchBinding, McpGenerationAuthority,
    McpServerKind, McpToolDescriptor, McpToolDispatchCapability, McpToolGateway, PublishedMcpTools,
    publish_mcp_tools,
};

use super::model::{
    FixtureApprovalPolicy, FixtureCallResult, FixtureIdentity, FixtureInitialize, FixtureLimits,
    FixtureScript, FixtureStepOutcome, FixtureTool,
};
use super::transport::{FixtureAdmission, FixtureClient};

static FIXTURE_ISSUER_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Safe fixture audit metadata; payloads and error text are never retained.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureAuditRecord {
    invocation_digest: [u8; 32],
    connection_digest: [u8; 32],
    generation: u64,
    bytes: usize,
    uncertain: bool,
}

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
}

pub(super) struct FixtureState {
    pub(super) active: Option<FixtureInitialize>,
    reconnect_required: Option<ReconnectRequirement>,
    reconnect_identity: Option<FixtureInitialize>,
    tick: u64,
    next_step: usize,
    remaining: u64,
    effects: BTreeMap<EffectKey, FixtureCallResult>,
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
    pub(super) invocation_id: String,
    pub(super) approval_digest: [u8; 32],
    pub(super) connection_id: String,
    pub(super) generation: u64,
    pub(super) expires_at: u64,
    pub(super) bytes: usize,
    pub(super) request_digest: [u8; 32],
    pub(super) issuer_digest: [u8; 32],
    pub(super) definition_digest: [u8; 32],
    pub(super) tool_name: String,
    pub(super) effect_key: EffectKey,
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
include!("runtime/dispatch.rs");
