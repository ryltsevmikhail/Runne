use std::collections::BTreeSet;
use std::fmt::Write as _;

use gocode_domain::agent_loop::{LoopDisposition, StepOutcomeType, WakeEvidenceSource};
use gocode_domain::command::TerminalResult;
use gocode_domain::conversation::{ConversationEvent, GenerationFailureReason};
use gocode_domain::event::{EventType, Sensitivity};
use gocode_domain::replay::ReplayScope;
use gocode_domain::task_run::TaskRunEvent;
use serde::Serialize;

use crate::{
    EphemeralRuntimeBinding, LocalSessionContractError, RuntimeSessionBinding, StableRuntimeBinding,
};

/// Maximum UTF-8 bytes in a public TaskRun failure reason.
pub const MAX_CANONICAL_REPLAY_FAILURE_REASON_BYTES: usize = 4096;

/// Aggregate streams exposed through the public replay API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApiReplayAggregateKind {
    /// Conversation aggregate stream.
    Conversation,
    /// Task run aggregate stream.
    TaskRun,
}

impl TryFrom<ReplayScope> for ApiReplayAggregateKind {
    type Error = ReplayContractError;

    fn try_from(scope: ReplayScope) -> Result<Self, Self::Error> {
        match scope {
            ReplayScope::Aggregate {
                aggregate_type: 1, ..
            } => Ok(Self::TaskRun),
            ReplayScope::Aggregate {
                aggregate_type: 2, ..
            } => Ok(Self::Conversation),
            ReplayScope::Aggregate { .. } => Err(ReplayContractError::UnknownAggregateKind),
            ReplayScope::TaskRunFeed { .. } | ReplayScope::AuditFeed { .. } => {
                Err(ReplayContractError::UnsupportedScope)
            }
        }
    }
}

/// Stable failures when adapting an internal replay scope to the public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayContractError {
    /// The domain aggregate selector is not public replay scope.
    UnknownAggregateKind,
    /// The domain scope is an internal feed rather than an aggregate stream.
    UnsupportedScope,
    /// A retention manifest did not contain a usable generation and digest.
    InvalidRetentionManifest,
    /// A gap-range reference was empty.
    InvalidGapRangeRef,
    /// An opaque replay binding identity was empty.
    EmptyBindingId,
    /// A supported canonical event type was empty.
    EmptyEventType,
    /// A supported canonical event type contained a forbidden control byte.
    InvalidEventType,
    /// A supported canonical event schema version was zero.
    InvalidEventSchemaVersion,
    /// A closed aggregate projection failed its integrity validation.
    InvalidProjection,
}

/// Opaque public replay-binding identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiReplayBindingId([u8; 16]);

impl ApiReplayBindingId {
    /// Creates a non-empty opaque replay-binding identity.
    pub fn new(value: [u8; 16]) -> Result<Self, ReplayContractError> {
        if value == [0; 16] {
            return Err(ReplayContractError::EmptyBindingId);
        }
        Ok(Self(value))
    }

    /// Returns the stable opaque lower-hex wire identity.
    ///
    /// This is a transport identity only; it does not expose storage position
    /// or authority material.
    pub fn to_wire_value(&self) -> String {
        let mut value = String::with_capacity(32);
        for byte in self.0 {
            write!(&mut value, "{byte:02x}").expect("writing to String is infallible");
        }
        value
    }
}

impl core::fmt::Debug for ApiReplayBindingId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ApiReplayBindingId([redacted])")
    }
}

/// A supported canonical event type and its schema version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiReplayEventSchema {
    event_type: String,
    schema_version: u32,
}

impl ApiReplayEventSchema {
    /// Creates a validated public event-type/schema capability.
    pub fn new(
        event_type: impl Into<String>,
        schema_version: u32,
    ) -> Result<Self, ReplayContractError> {
        let event_type = event_type.into();
        if event_type.is_empty() {
            return Err(ReplayContractError::EmptyEventType);
        }
        let event_type = EventType::new(event_type)
            .map_err(|_| ReplayContractError::InvalidEventType)?
            .as_str()
            .to_owned();
        if schema_version == 0 {
            return Err(ReplayContractError::InvalidEventSchemaVersion);
        }
        Ok(Self {
            event_type,
            schema_version,
        })
    }

    /// Returns the canonical event type.
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Returns the supported event schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

/// Retention generation and opaque manifest digest for replay continuity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionManifest {
    generation: u64,
    digest: [u8; 32],
}

impl RetentionManifest {
    /// Creates a non-empty retention manifest reference.
    pub fn new(generation: u64, digest: [u8; 32]) -> Result<Self, ReplayContractError> {
        if generation == 0 || digest == [0; 32] {
            return Err(ReplayContractError::InvalidRetentionManifest);
        }
        Ok(Self { generation, digest })
    }

    /// Returns the retention generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Opaque reference to a compacted replay gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapRangeRef([u8; 32]);

impl GapRangeRef {
    /// Creates a non-empty opaque gap reference.
    pub fn new(reference: [u8; 32]) -> Result<Self, ReplayContractError> {
        if reference == [0; 32] {
            return Err(ReplayContractError::InvalidGapRangeRef);
        }
        Ok(Self(reference))
    }
}

/// Public replay binding version one.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiReplayBindingV1 {
    binding_id: ApiReplayBindingId,
    stable: StableRuntimeBinding,
    ephemeral: EphemeralRuntimeBinding,
    supported_event_schemas: BTreeSet<ApiReplayEventSchema>,
    replay_session_id: [u8; 16],
    retention_manifest: RetentionManifest,
}

impl ApiReplayBindingV1 {
    /// Creates a replay binding tied exactly to one local runtime session.
    pub fn new(
        binding_id: ApiReplayBindingId,
        session: RuntimeSessionBinding,
        authorization_epoch: u64,
        sensitivity_ceiling: Sensitivity,
        supported_event_schemas: impl IntoIterator<Item = ApiReplayEventSchema>,
        replay_session_id: [u8; 16],
        retention_manifest: RetentionManifest,
    ) -> Result<Self, LocalSessionContractError> {
        if authorization_epoch != session.ephemeral().authorization_epoch() {
            return Err(LocalSessionContractError::AuthorizationEpochMismatch);
        }
        if sensitivity_ceiling != session.ephemeral().sensitivity_ceiling() {
            return Err(LocalSessionContractError::SensitivityCeilingMismatch);
        }
        Ok(Self {
            binding_id,
            stable: session.stable().clone(),
            ephemeral: session.ephemeral().clone(),
            supported_event_schemas: supported_event_schemas.into_iter().collect(),
            replay_session_id,
            retention_manifest,
        })
    }

    /// Returns the stable runtime binding.
    pub const fn stable(&self) -> &StableRuntimeBinding {
        &self.stable
    }

    /// Returns the opaque replay-binding identity.
    pub const fn binding_id(&self) -> &ApiReplayBindingId {
        &self.binding_id
    }

    /// Returns the ephemeral runtime binding.
    pub const fn ephemeral(&self) -> &EphemeralRuntimeBinding {
        &self.ephemeral
    }

    /// Returns the supported canonical event-type/schema pairs.
    pub fn supported_event_schemas(&self) -> impl Iterator<Item = &ApiReplayEventSchema> {
        self.supported_event_schemas.iter()
    }

    /// Returns the opaque replay-session identity.
    pub const fn replay_session_id(&self) -> &[u8; 16] {
        &self.replay_session_id
    }

    /// Returns the retention manifest reference.
    pub const fn retention_manifest(&self) -> &RetentionManifest {
        &self.retention_manifest
    }
}

impl core::fmt::Debug for ApiReplayBindingV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApiReplayBindingV1")
            .field("stable", &self.stable)
            .field("ephemeral", &self.ephemeral)
            .field("supported_event_schemas", &self.supported_event_schemas)
            .field("retention_manifest", &self.retention_manifest)
            .finish_non_exhaustive()
    }
}
