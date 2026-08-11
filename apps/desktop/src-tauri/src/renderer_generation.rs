use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::directory_selection::{SelectionEntry, valid_binding};

const MAX_TRACKED_WINDOWS: usize = 64;

/// Closed failure for unavailable or stale native renderer state.
#[derive(Debug, Error)]
#[error("renderer generation rejected")]
pub struct RendererGenerationError;

pub type SharedSelectionState = Arc<Mutex<DirectorySelectionState>>;

pub struct DirectorySelectionState {
    pub(super) generations: HashMap<String, u64>,
    pub(super) selections: HashMap<String, SelectionEntry>,
}

impl DirectorySelectionState {
    pub(super) fn register_generation(
        &mut self,
        window: &str,
    ) -> Result<u64, RendererGenerationError> {
        if !valid_binding(window) {
            return Err(RendererGenerationError);
        }
        if !self.generations.contains_key(window) && self.generations.len() >= MAX_TRACKED_WINDOWS {
            return Err(RendererGenerationError);
        }
        Ok(*self.generations.entry(window.to_owned()).or_insert(0))
    }

    pub(super) fn existing_generation(&self, window: &str) -> Result<u64, RendererGenerationError> {
        valid_binding(window)
            .then(|| self.generations.get(window).copied())
            .flatten()
            .ok_or(RendererGenerationError)
    }

    pub(super) fn advance(&mut self, window: &str) -> Result<u64, RendererGenerationError> {
        let generation = self.register_generation(window)?;
        let next = generation.checked_add(1).ok_or(RendererGenerationError)?;
        self.generations.insert(window.to_owned(), next);
        self.selections.retain(|_, entry| entry.window != window);
        Ok(next)
    }
}

/// Native-only view of the shared selection generation state.
pub struct RendererGenerationManager {
    state: SharedSelectionState,
}

impl RendererGenerationManager {
    pub(super) const fn from_shared_state(state: SharedSelectionState) -> Self {
        Self { state }
    }

    /// Returns the active generation, registering a host window only once.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid labels, poisoned state, or capacity exhaustion.
    pub fn current(&self, window: &str) -> Result<u64, RendererGenerationError> {
        self.state
            .lock()
            .map_err(|_| RendererGenerationError)?
            .register_generation(window)
    }

    /// Atomically advances a renderer generation and invalidates its selections.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid labels, poisoned state, or overflow.
    pub fn fence_reload(&self, window: &str) -> Result<u64, RendererGenerationError> {
        self.state
            .lock()
            .map_err(|_| RendererGenerationError)?
            .advance(window)
    }

    /// Atomically fences destruction and invalidates all pending selections.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid labels, poisoned state, or overflow.
    pub fn fence_destroyed(&self, window: &str) -> Result<u64, RendererGenerationError> {
        self.fence_reload(window)
    }

    #[cfg(feature = "test-support")]
    /// Sets an exact generation solely for overflow coverage.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid labels or poisoned state.
    pub fn set_generation_for_test(
        &self,
        window: &str,
        generation: u64,
    ) -> Result<(), RendererGenerationError> {
        let mut state = self.state.lock().map_err(|_| RendererGenerationError)?;
        state.register_generation(window)?;
        state.generations.insert(window.to_owned(), generation);
        drop(state);
        Ok(())
    }
}

impl Clone for RendererGenerationManager {
    fn clone(&self) -> Self {
        Self::from_shared_state(Arc::clone(&self.state))
    }
}

impl std::fmt::Debug for RendererGenerationManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RendererGenerationManager(<native-only>)")
    }
}
