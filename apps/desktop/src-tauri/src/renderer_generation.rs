use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;

const MAX_WINDOW_LABEL_BYTES: usize = 128;
const MAX_TRACKED_WINDOWS: usize = 64;

/// Closed failure for untrusted or excessive renderer window labels.
#[derive(Debug, Error)]
#[error("renderer generation rejected")]
pub struct RendererGenerationError;

/// Monotonic renderer generations retained by the native host.
#[derive(Debug, Default)]
pub struct RendererGenerationManager {
    generations: Mutex<HashMap<String, u64>>,
}

impl RendererGenerationManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the active generation, registering a window only once.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid or excessive window labels.
    pub fn current(&self, window: &str) -> Result<u64, RendererGenerationError> {
        self.with_generation(window, false)
    }

    /// Advances the window generation after a renderer reload.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid or excessive window labels.
    pub fn fence_reload(&self, window: &str) -> Result<u64, RendererGenerationError> {
        self.with_generation(window, true)
    }

    /// Advances the window generation after destruction without deleting history.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid or excessive window labels.
    pub fn fence_destroyed(&self, window: &str) -> Result<u64, RendererGenerationError> {
        self.with_generation(window, true)
    }

    #[cfg(feature = "test-support")]
    pub fn set_generation_for_test(
        &self,
        window: &str,
        generation: u64,
    ) -> Result<(), RendererGenerationError> {
        if !valid_window(window) {
            return Err(RendererGenerationError);
        }
        let mut generations = self
            .generations
            .lock()
            .map_err(|_| RendererGenerationError)?;
        generations.insert(window.to_owned(), generation);
        Ok(())
    }

    fn with_generation(&self, window: &str, advance: bool) -> Result<u64, RendererGenerationError> {
        if !valid_window(window) {
            return Err(RendererGenerationError);
        }
        let mut generations = self
            .generations
            .lock()
            .map_err(|_| RendererGenerationError)?;
        if !generations.contains_key(window) && generations.len() == MAX_TRACKED_WINDOWS {
            return Err(RendererGenerationError);
        }
        let result = {
            let generation = generations.entry(window.to_owned()).or_insert(0);
            if advance {
                *generation = generation.checked_add(1).ok_or(RendererGenerationError)?;
            }
            *generation
        };
        drop(generations);
        Ok(result)
    }
}

fn valid_window(window: &str) -> bool {
    !window.is_empty()
        && window.len() <= MAX_WINDOW_LABEL_BYTES
        && window.is_ascii()
        && !window.chars().any(char::is_control)
}
