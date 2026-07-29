//! Typed errors for baseline session creation.

use gocode_api::{HostError, ValidationError};

use crate::binding::{BindingError, SessionBindingKey};
use crate::profile::ProfileRef;

/// Fail-closed error from `session.create` orchestration.
#[derive(Debug, Clone)]
pub enum SessionCreateError {
    /// The request contains a baseline field not supported by this profile.
    UnsupportedField { field: &'static str },
    /// The supplied key belongs to a profile not loaded by this service.
    ProfileMismatch {
        configured: ProfileRef,
        requested: SessionBindingKey,
    },
    /// The service itself was configured with a profile that cannot create sessions.
    UnsupportedProfile { configured: ProfileRef },
    /// An existing binding has a different canonical context or wire payload.
    ContextConflict { key: SessionBindingKey },
    /// The store reported committed but did not retain the committed response.
    ImpossibleCommittedBinding { key: SessionBindingKey },
    /// The idempotent host returned a different canonical identity.
    HostOutputMismatch { key: SessionBindingKey },
    /// Binding durability operation failed.
    Binding(BindingError),
    /// Host creation operation failed before durable completion.
    Host(HostError),
    /// The constructed response did not satisfy the supplied wire schema.
    Validation(ValidationError),
}

/// Error returned when a recovery list request is outside its bounded contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryListError {
    /// The caller requested zero or more than the supported maximum entries.
    InvalidLimit { max: usize, actual: usize },
    /// The binding adapter failed to list pending entries.
    Binding(BindingError),
}

/// Closed host failures for the OpenCode V1 session compatibility surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionV1HostError {
    NotFound,
    Conflict,
    StorageFailure,
    Timeout,
}

/// Fail-closed error from the OpenCode V1 session compatibility surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionV1Error {
    InvalidSessionId,
    InvalidRequest { detail: &'static str },
    UnsupportedField { field: &'static str },
    UnsupportedPart { index: usize },
    HostOutputMismatch,
    Host(SessionV1HostError),
}
