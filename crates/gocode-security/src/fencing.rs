//! fencing module

use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum FencingError {
    #[error("owner is cancelled")]
    Cancelled,
    #[error("cancellation fence is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct DispatchClaim {
    owner: String,
}

impl DispatchClaim {
    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn is_admitted(&self) -> bool {
        true
    }
}

pub struct CancellationFence {
    cancelled: Mutex<HashSet<String>>,
}

impl CancellationFence {
    pub fn new() -> Self {
        Self {
            cancelled: Mutex::new(HashSet::new()),
        }
    }

    pub fn cancel(&self, owner: &str) -> Result<(), FencingError> {
        self.cancelled
            .lock()
            .map_err(|_| FencingError::Unavailable)?
            .insert(owner.to_string());
        Ok(())
    }

    pub fn claim_dispatch(&self, owner: &str) -> Result<DispatchClaim, FencingError> {
        if self
            .cancelled
            .lock()
            .map_err(|_| FencingError::Unavailable)?
            .contains(owner)
        {
            return Err(FencingError::Cancelled);
        }
        Ok(DispatchClaim {
            owner: owner.to_string(),
        })
    }
}

impl Default for CancellationFence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_before_claim_fences_dispatch() {
        let fence = CancellationFence::new();
        fence.cancel("run-1").unwrap();

        let result = fence.claim_dispatch("run-1");

        assert!(matches!(result, Err(FencingError::Cancelled)));
    }

    #[test]
    fn admitted_claim_survives_later_cancel_but_new_claim_is_fenced() {
        let fence = CancellationFence::new();
        let claim = fence.claim_dispatch("run-2").unwrap();

        fence.cancel("run-2").unwrap();

        assert!(claim.is_admitted());
        assert!(matches!(
            fence.claim_dispatch("run-2"),
            Err(FencingError::Cancelled)
        ));
    }
}
