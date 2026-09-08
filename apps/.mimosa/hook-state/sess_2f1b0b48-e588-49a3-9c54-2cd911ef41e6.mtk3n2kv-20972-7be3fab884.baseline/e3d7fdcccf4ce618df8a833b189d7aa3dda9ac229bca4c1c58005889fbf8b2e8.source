use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use thiserror::Error;

use crate::directory_selection::{SelectionEntry, valid_binding};
use crate::prepared_workspace::{PreparedWorkspaceEntry, PreparedWorkspaceReservation};

const MAX_TRACKED_WINDOWS: usize = 64;

/// Closed failure for unavailable or stale native renderer state.
#[derive(Debug, Error)]
#[error("renderer generation rejected")]
pub struct RendererGenerationError;

pub type SharedSelectionState = Arc<Mutex<DirectorySelectionState>>;

pub struct DirectorySelectionState {
    pub(super) generations: HashMap<String, u64>,
    pub(super) selections: HashMap<String, SelectionEntry>,
    pub(super) prepared: HashMap<String, PreparedWorkspaceEntry>,
    pub(super) reservations: HashMap<String, PreparedWorkspaceReservation>,
    pub(super) prepared_ttl: Duration,
    pub(super) expiry_sweeper_running: bool,
    #[cfg(test)]
    pub(super) expiry_sweeper_start_fails_for_test: bool,
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
        self.prepared.retain(|_, entry| {
            if entry.window != window {
                return true;
            }
            match entry.phase {
                crate::prepared_workspace::PreparedWorkspacePhase::Ready => false,
                crate::prepared_workspace::PreparedWorkspacePhase::Attempting {
                    attempt_id,
                    ..
                } => {
                    entry.phase = crate::prepared_workspace::PreparedWorkspacePhase::Attempting {
                        attempt_id,
                        revoked: true,
                    };
                    true
                }
                crate::prepared_workspace::PreparedWorkspacePhase::Retained => {
                    entry.root.take();
                    entry.admission.take();
                    entry.operation_permit.take();
                    entry.prepared_open.take();
                    entry.phase = crate::prepared_workspace::PreparedWorkspacePhase::Orphaned;
                    true
                }
                crate::prepared_workspace::PreparedWorkspacePhase::Orphaned
                | crate::prepared_workspace::PreparedWorkspacePhase::Opened => true,
            }
        });
        self.reservations.retain(|_, entry| entry.window != window);
        Ok(next)
    }

    pub(super) fn page_loaded(&mut self, window: &str) -> Result<u64, RendererGenerationError> {
        if !valid_binding(window) {
            return Err(RendererGenerationError);
        }
        if self.generations.contains_key(window) {
            return self.advance(window);
        }
        if self.generations.len() >= MAX_TRACKED_WINDOWS {
            return Err(RendererGenerationError);
        }
        self.generations.insert(window.to_owned(), 1);
        Ok(1)
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

    /// Returns an already host-issued active generation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid, unregistered, or poisoned host state.
    pub fn current(&self, window: &str) -> Result<u64, RendererGenerationError> {
        self.state
            .lock()
            .map_err(|_| RendererGenerationError)?
            .existing_generation(window)
    }

    /// Fences prior renderer-owned values for a native page load or navigation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid labels, overflow, or poisoned host state.
    pub fn page_loaded(&self, window: &str) -> Result<u64, RendererGenerationError> {
        self.state
            .lock()
            .map_err(|_| RendererGenerationError)?
            .page_loaded(window)
    }

    /// Atomically advances a renderer generation and invalidates its selections.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid labels, poisoned state, or overflow.
    #[cfg(test)]
    #[allow(dead_code)] // Unit test lifecycle hook.
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
        let mut state = self.state.lock().map_err(|_| RendererGenerationError)?;
        let next = state.advance(window)?;
        drop(state);
        Ok(next)
    }

    #[cfg(test)]
    #[allow(dead_code)] // Unit test overflow hook.
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
