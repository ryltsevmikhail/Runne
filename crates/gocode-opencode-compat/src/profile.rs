//! Profile types — std-only, zero deps.

use crate::classify::{
    CompatibilityClass, ImplementationStatus, RejectionCode, RejectionRationale,
};

/// Bounded profile identifier (no revision suffix).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileId(pub String);

/// Profile revision number.
pub type ProfileRevision = u16;

/// Normalized route selector.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperationSelector {
    pub transport: Transport,
    pub method: String,
    pub normalized_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    HTTP,
    SSE,
    WebSocket,
    Internal,
}

/// Typed rejection for any operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRejection {
    pub profile_id: ProfileId,
    pub profile_revision: ProfileRevision,
    pub attempted_selector: OperationSelector,
    pub inventory_id: Option<String>,
    pub upstream_operation_id: Option<String>,
    pub code: RejectionCode,
    pub rationale: Option<RejectionRationale>,
    pub detail: Option<String>,
}

/// Phase 2a: все операции — Reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslationDecision {
    Reject(ProfileRejection),
}
