//! Shared generation-fencing contract for protected migration boundaries.

use super::types::{FencingToken, RoutingGeneration};

/// Typed failure returned before protected migration work is dispatched or confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceError {
    /// The attempted routing generation is older than the active fence.
    StaleFencingToken {
        /// Active routing generation.
        current_generation: RoutingGeneration,
        /// Generation carried by the attempted work.
        attempted_generation: RoutingGeneration,
    },
    /// The attempted generation is newer than the locally active fence.
    FutureRoutingGeneration {
        /// Active routing generation.
        current_generation: RoutingGeneration,
        /// Generation carried by the attempted work.
        attempted_generation: RoutingGeneration,
    },
    /// Generation matched but the opaque fencing token did not.
    TokenMismatch,
    /// A registry update attempted to move to an older generation.
    GenerationRegression {
        /// Active routing generation.
        current_generation: RoutingGeneration,
        /// Proposed routing generation.
        attempted_generation: RoutingGeneration,
    },
    /// A different token was proposed for an already active generation.
    ConflictingToken,
    /// An authorization counter could not be incremented.
    CounterExhausted,
    /// Fence state could not be read or updated.
    Unavailable,
}

/// Validation port used at every protected migration dispatch and confirmation boundary.
pub trait FenceValidationPort: Send + Sync {
    /// Validate the generation and token immediately before dispatch.
    fn validate_dispatch(
        &self,
        generation: RoutingGeneration,
        token: FencingToken,
    ) -> Result<(), FenceError>;

    /// Validate the generation and token immediately before effect confirmation.
    fn validate_confirmation(
        &self,
        generation: RoutingGeneration,
        token: FencingToken,
    ) -> Result<(), FenceError>;
}
