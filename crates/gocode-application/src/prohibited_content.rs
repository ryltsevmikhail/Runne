//! Transport-free boundary for rejecting registered secret material.

use thiserror::Error;

/// Canonical boundary at which content is inspected before it can escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalContentBoundary {
    /// Content is about to enter authoritative canonical state.
    CanonicalMutation,
    /// Content is about to be delivered outside the runtime boundary.
    OutboundDelivery,
}

/// Non-sensitive outcome of prohibited-content inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentDisposition {
    /// No active registered value was found.
    Allowed {
        /// Policy epoch observed during inspection.
        policy_epoch: u64,
    },
    /// Content must not cross this boundary.
    Prohibited {
        /// Policy epoch observed during inspection.
        policy_epoch: u64,
    },
}

/// The prohibited-content policy could not be consulted safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ContentGuardError {
    /// Registry state is unavailable or inconsistent.
    #[error("prohibited-content registry unavailable")]
    Unavailable,
}

/// Application port for inspecting bytes before canonical mutation or delivery.
pub trait ProhibitedContentPort: Send + Sync {
    /// Returns the longest active representation required for boundary withholding.
    fn maximum_match_len(&self) -> Result<usize, ContentGuardError> {
        Err(ContentGuardError::Unavailable)
    }

    /// Returns a non-sensitive disposition for the supplied bytes.
    fn inspect(
        &self,
        boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError>;
}
