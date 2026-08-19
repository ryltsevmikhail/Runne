//! Monotonic platform fencing at protected effect boundaries.

use std::sync::{
    RwLock,
    atomic::{AtomicU64, Ordering},
};

use runne_application::migration::{
    fence::{FenceError, FenceValidationPort},
    types::{FencingToken, RoutingGeneration},
};

/// Active platform fence and successful protected-boundary counters.
#[derive(Debug)]
pub struct FenceRegistry {
    active: RwLock<ActiveFence>,
    dispatched: AtomicU64,
    confirmed: AtomicU64,
}

impl FenceRegistry {
    /// Create a registry at an already validated generation and token.
    pub fn new(generation: RoutingGeneration, token: FencingToken) -> Self {
        Self {
            active: RwLock::new(ActiveFence { generation, token }),
            dispatched: AtomicU64::new(0),
            confirmed: AtomicU64::new(0),
        }
    }

    /// Monotonically activate a newer fence.
    ///
    /// Repeating the exact active fence is idempotent. A conflicting token at
    /// the same generation and every generation regression are rejected.
    pub fn activate(
        &self,
        generation: RoutingGeneration,
        token: FencingToken,
    ) -> Result<(), FenceError> {
        let mut active = self.active.write().map_err(|_| FenceError::Unavailable)?;
        if generation < active.generation {
            return Err(FenceError::GenerationRegression {
                current_generation: active.generation,
                attempted_generation: generation,
            });
        }
        if generation == active.generation {
            return if token == active.token {
                Ok(())
            } else {
                Err(FenceError::ConflictingToken)
            };
        }
        *active = ActiveFence { generation, token };
        Ok(())
    }

    /// Validate and execute one protected dispatch under the active fence.
    ///
    /// The active-fence read lock is held until `effect` returns, so a
    /// concurrent activation cannot invalidate the authorization between
    /// validation and the protected dispatch.
    pub fn authorize_dispatch<T>(
        &self,
        generation: RoutingGeneration,
        token: FencingToken,
        effect: impl FnOnce() -> T,
    ) -> Result<T, FenceError> {
        let active = self.active.read().map_err(|_| FenceError::Unavailable)?;
        validate(&active, generation, token)?;
        increment(&self.dispatched)?;
        Ok(effect())
    }

    /// Validate and execute one protected confirmation under the active fence.
    pub fn authorize_confirmation<T>(
        &self,
        generation: RoutingGeneration,
        token: FencingToken,
        effect: impl FnOnce() -> T,
    ) -> Result<T, FenceError> {
        let active = self.active.read().map_err(|_| FenceError::Unavailable)?;
        validate(&active, generation, token)?;
        increment(&self.confirmed)?;
        Ok(effect())
    }

    /// Return the number of successful protected dispatch authorizations.
    pub fn dispatched_count(&self) -> u64 {
        self.dispatched.load(Ordering::Acquire)
    }

    /// Return the number of successful protected confirmation authorizations.
    pub fn confirmed_count(&self) -> u64 {
        self.confirmed.load(Ordering::Acquire)
    }
}

impl FenceValidationPort for FenceRegistry {
    fn validate_dispatch(
        &self,
        generation: RoutingGeneration,
        token: FencingToken,
    ) -> Result<(), FenceError> {
        let active = self.active.read().map_err(|_| FenceError::Unavailable)?;
        validate(&active, generation, token)
    }

    fn validate_confirmation(
        &self,
        generation: RoutingGeneration,
        token: FencingToken,
    ) -> Result<(), FenceError> {
        let active = self.active.read().map_err(|_| FenceError::Unavailable)?;
        validate(&active, generation, token)
    }
}

#[derive(Debug, Clone, Copy)]
struct ActiveFence {
    generation: RoutingGeneration,
    token: FencingToken,
}

fn validate(
    active: &ActiveFence,
    generation: RoutingGeneration,
    token: FencingToken,
) -> Result<(), FenceError> {
    if generation < active.generation {
        return Err(FenceError::StaleFencingToken {
            current_generation: active.generation,
            attempted_generation: generation,
        });
    }
    if generation > active.generation {
        return Err(FenceError::FutureRoutingGeneration {
            current_generation: active.generation,
            attempted_generation: generation,
        });
    }
    if token != active.token {
        return Err(FenceError::TokenMismatch);
    }
    Ok(())
}

fn increment(counter: &AtomicU64) -> Result<(), FenceError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map(|_| ())
        .map_err(|_| FenceError::CounterExhausted)
}
