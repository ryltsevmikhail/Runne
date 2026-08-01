//! Session envelope — post-handshake message framing with full correlation model.
//!
//! Every post-handshake message is wrapped in a `SessionEnvelope` that carries
//! session identity, direction, correlation, deadlines, digests, sensitivity,
//! and ancillary handle declarations.

use crate::bootstrap::HostExecutionIdentity;
use crate::digest::{
    MessageDigest, PayloadDigest, ProfileDigest, SchemaBundleDigest, Sha256Digest,
    WireContractDigest,
};
use crate::id::{
    ControlCorrelationId, ControlIntentId, DeadlineUnixMillis, InvocationId, MessageTypeId,
    ProfileId, ProtocolSessionId, ProtocolVersion, RequestId, SchemaRevision, WireAttemptId,
    WireTaskRunId,
};

// ── Direction ──────────────────────────────────────────────────────────────

/// Message direction within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Host → Plugin.
    HostToPlugin,
    /// Plugin → Host.
    PluginToHost,
}

// ── Sensitivity ────────────────────────────────────────────────────────────

/// Sensitivity classification for wire data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensitivity {
    /// Public — may be logged and relayed freely.
    Public,
    /// Internal — restricted to the runtime process.
    Internal,
    /// Sensitive — contains secrets, must be redacted in diagnostics.
    Sensitive,
}

// ── AncillaryHandleType / AncillaryHandleDeclaration ───────────────────────

/// Semantically typed handle reference — never an OS handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AncillaryHandleType {
    /// Immutable data region for read-only shared access.
    ImmutableReadRegion,
    /// Mutable buffer for candidate output (write-only).
    CandidateWriteBuffer,
    /// Shared memory region with declared access pattern.
    SharedMemoryRegion,
}

/// Declaration of an ancillary handle to be attached to a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncillaryHandleDeclaration {
    /// Number of handles of this type.
    pub count: u32,
    /// The semantic type.
    pub handle_type: AncillaryHandleType,
    /// Binding digest for validation.
    pub binding_digest: Sha256Digest,
}

// ── MessageCorrelation ────────────────────────────────────────────────────

/// Message correlation model — disambiguates invocation vs control messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageCorrelation {
    /// Invocation correlation: request + invocation + optional permit.
    Invocation {
        request_id: RequestId,
        invocation_id: InvocationId,
        invocation_permit: Option<InvocationPermitRef>,
    },
    /// Control message correlation.
    Control {
        correlation_id: ControlCorrelationId,
        intent_id: ControlIntentId,
    },
}

/// Opaque reference to an invocation permit (host-controlled resource).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvocationPermitRef(u64);

impl InvocationPermitRef {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
    pub const fn value(&self) -> u64 {
        self.0
    }
}

// ── SessionEnvelope ───────────────────────────────────────────────────────

/// Post-handshake session message envelope.
///
/// Carries full session identity, correlation, deadlines, digests, and
/// sensitivity. The generic parameter `M` is the message payload type.
#[derive(Debug, Clone)]
pub struct SessionEnvelope<M> {
    pub(crate) session_id: ProtocolSessionId,
    pub(crate) profile_id: ProfileId,
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) wire_contract_digest: WireContractDigest,
    pub(crate) schema_bundle_digest: SchemaBundleDigest,
    pub(crate) direction: Direction,
    pub(crate) sequence: u64,
    pub(crate) message_type_id: MessageTypeId,
    pub(crate) schema_revision: SchemaRevision,
    pub(crate) host_identity: HostExecutionIdentity,
    pub(crate) taskrun_id: WireTaskRunId,
    pub(crate) attempt_id: WireAttemptId,
    pub(crate) correlation: MessageCorrelation,
    pub(crate) deadline: DeadlineUnixMillis,
    pub(crate) message_digest: MessageDigest,
    pub(crate) payload_digest: PayloadDigest,
    pub(crate) profile_digest: ProfileDigest,
    pub(crate) sensitivity: Sensitivity,
    pub(crate) ancillary_handles: Vec<AncillaryHandleDeclaration>,
    pub(crate) message: M,
}

impl<M> SessionEnvelope<M> {
    /// Create a new session envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: ProtocolSessionId,
        profile_id: ProfileId,
        protocol_version: ProtocolVersion,
        wire_contract_digest: WireContractDigest,
        schema_bundle_digest: SchemaBundleDigest,
        direction: Direction,
        sequence: u64,
        message_type_id: MessageTypeId,
        schema_revision: SchemaRevision,
        host_identity: HostExecutionIdentity,
        taskrun_id: WireTaskRunId,
        attempt_id: WireAttemptId,
        correlation: MessageCorrelation,
        deadline: DeadlineUnixMillis,
        message_digest: MessageDigest,
        payload_digest: PayloadDigest,
        profile_digest: ProfileDigest,
        sensitivity: Sensitivity,
        ancillary_handles: Vec<AncillaryHandleDeclaration>,
        message: M,
    ) -> Self {
        Self {
            session_id,
            profile_id,
            protocol_version,
            wire_contract_digest,
            schema_bundle_digest,
            direction,
            sequence,
            message_type_id,
            schema_revision,
            host_identity,
            taskrun_id,
            attempt_id,
            correlation,
            deadline,
            message_digest,
            payload_digest,
            profile_digest,
            sensitivity,
            ancillary_handles,
            message,
        }
    }

    // Accessor methods
    pub fn session_id(&self) -> &ProtocolSessionId {
        &self.session_id
    }
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
    pub fn wire_contract_digest(&self) -> &WireContractDigest {
        &self.wire_contract_digest
    }
    pub fn schema_bundle_digest(&self) -> &SchemaBundleDigest {
        &self.schema_bundle_digest
    }
    pub fn direction(&self) -> Direction {
        self.direction
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn message_type_id(&self) -> MessageTypeId {
        self.message_type_id
    }
    pub fn schema_revision(&self) -> SchemaRevision {
        self.schema_revision
    }
    pub fn host_identity(&self) -> &HostExecutionIdentity {
        &self.host_identity
    }
    pub fn taskrun_id(&self) -> &WireTaskRunId {
        &self.taskrun_id
    }
    pub fn attempt_id(&self) -> &WireAttemptId {
        &self.attempt_id
    }
    pub fn correlation(&self) -> &MessageCorrelation {
        &self.correlation
    }
    pub fn deadline(&self) -> DeadlineUnixMillis {
        self.deadline
    }
    pub fn message_digest(&self) -> &MessageDigest {
        &self.message_digest
    }
    pub fn payload_digest(&self) -> &PayloadDigest {
        &self.payload_digest
    }
    pub fn profile_digest(&self) -> &ProfileDigest {
        &self.profile_digest
    }
    pub fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
    pub fn ancillary_handles(&self) -> &[AncillaryHandleDeclaration] {
        &self.ancillary_handles
    }
    pub fn message(&self) -> &M {
        &self.message
    }

    /// Consume the envelope and return the message, discarding metadata.
    pub fn into_message(self) -> M {
        self.message
    }
}

#[cfg(test)]
mod tests {
    include!("session/tests.rs");
}
