//! Runtime ingress and worker fencing for migration-scoped dispatch.

use std::sync::Arc;

use runne_application::migration::{
    fence::{FenceError, FenceValidationPort},
    types::{FencingToken, RoutingGeneration},
};

/// Fence evidence admitted at runtime ingress and carried to the worker boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedIngressFence {
    generation: RoutingGeneration,
    token: FencingToken,
}

impl ValidatedIngressFence {
    /// Return the admitted routing generation.
    pub fn generation(self) -> RoutingGeneration {
        self.generation
    }

    /// Return the admitted opaque fencing token.
    pub fn token(self) -> FencingToken {
        self.token
    }
}

/// Revalidates one admitted fence at each runtime migration boundary.
#[derive(Debug)]
pub struct MigrationFenceGuard<V: ?Sized> {
    validator: Arc<V>,
}

impl<V: FenceValidationPort + ?Sized> MigrationFenceGuard<V> {
    /// Construct a guard around the current fence validation authority.
    pub fn new(validator: Arc<V>) -> Self {
        Self { validator }
    }

    /// Validate a migration request before it enters a worker mailbox.
    pub fn validate_ingress(
        &self,
        generation: RoutingGeneration,
        token: FencingToken,
    ) -> Result<ValidatedIngressFence, FenceError> {
        self.validator.validate_dispatch(generation, token)?;
        Ok(ValidatedIngressFence { generation, token })
    }

    /// Revalidate an admitted request immediately before worker dispatch.
    pub fn validate_worker_dispatch(
        &self,
        admitted: &ValidatedIngressFence,
    ) -> Result<(), FenceError> {
        self.validator
            .validate_dispatch(admitted.generation, admitted.token)
    }

    /// Revalidate an admitted request immediately before effect confirmation.
    pub fn validate_confirmation(
        &self,
        admitted: &ValidatedIngressFence,
    ) -> Result<(), FenceError> {
        self.validator
            .validate_confirmation(admitted.generation, admitted.token)
    }
}
