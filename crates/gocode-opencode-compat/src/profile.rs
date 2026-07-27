//! Profile types — std-only, zero deps.

use crate::classify::{RejectionCode, RejectionRationale};

/// Bounded profile identifier (no revision suffix).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileId(String);

impl ProfileId {
    /// Validates and creates a profile identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ProfileIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ProfileIdError::Empty);
        }
        if value.len() > 256 {
            return Err(ProfileIdError::TooLong {
                actual: value.len(),
            });
        }
        if value
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
        {
            return Err(ProfileIdError::InvalidChar);
        }
        Ok(Self(value))
    }

    /// Returns the canonical profile identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reason a profile identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileIdError {
    Empty,
    TooLong { actual: usize },
    InvalidChar,
}

/// Profile revision number.
pub type ProfileRevision = u16;

/// The sole baseline profile that currently enables `session.create`.
pub const OPENCODE_BASELINE_INVENTORY_PROFILE_ID: &str = "opencode-baseline-inventory";

/// The sole profile revision that currently enables `session.create`.
pub const SESSION_CREATE_PROFILE_REVISION: ProfileRevision = 2;

/// Reference to the loaded compatibility profile used by a service instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRef {
    /// Stable profile identifier.
    pub profile_id: ProfileId,
    /// Loaded profile revision. Revision 2 enables `session.create`.
    pub profile_revision: ProfileRevision,
}

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
