use std::collections::{HashMap, hash_map::Entry};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gocode_platform_desktop::VerifiedRootHandle;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::prepared_workspace::PreparedWorkspaceManager;
use crate::renderer_generation::{
    DirectorySelectionState, RendererGenerationManager, SharedSelectionState,
};
const MAX_BINDING_BYTES: usize = 128;
pub const MAX_SELECTIONS: usize = 64;
const MAX_SELECTION_TTL: Duration = Duration::from_secs(30);

/// Opaque, renderer-safe reference to one host-retained directory handle.
pub struct DirectorySelectionRef(String);

impl Serialize for DirectorySelectionRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DirectorySelectionRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for DirectorySelectionRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectorySelectionRef(<redacted>)")
    }
}

impl DirectorySelectionRef {
    /// Parses only the exact bounded lowercase-hex reference format.
    ///
    /// # Errors
    ///
    /// Returns a closed error for any noncanonical renderer value.
    pub fn parse(value: &str) -> Result<Self, SelectionError> {
        valid_reference(value)
            .then(|| Self(value.to_owned()))
            .ok_or(SelectionError)
    }
}

/// Closed result for opaque selection validation.
#[derive(Debug, Error)]
#[error("directory selection rejected")]
pub struct SelectionError;
pub struct SelectionEntry {
    pub(super) window: String,
    generation: u64,
    request: String,
    root: VerifiedRootHandle,
    expires_at: Instant,
}

/// Native owner of handles and their authoritative renderer generations.
pub struct DirectorySelectionManager {
    ttl: Duration,
    state: SharedSelectionState,
}

impl DirectorySelectionManager {
    /// Creates a bounded native selection manager.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a zero or overlong reference lifetime.
    pub fn new(ttl: Duration) -> Result<Self, SelectionError> {
        if ttl.is_zero() || ttl > MAX_SELECTION_TTL {
            return Err(SelectionError);
        }
        Ok(Self {
            ttl,
            state: Arc::new(Mutex::new(DirectorySelectionState {
                generations: HashMap::default(),
                selections: HashMap::default(),
                prepared: HashMap::default(),
                reservations: HashMap::default(),
                prepared_ttl: ttl,
                expiry_sweeper_running: false,
                #[cfg(test)]
                expiry_sweeper_start_fails_for_test: false,
            })),
        })
    }

    /// Returns the only generation manager associated with this selection state.
    #[must_use]
    pub fn renderer_generations(&self) -> RendererGenerationManager {
        RendererGenerationManager::from_shared_state(Arc::clone(&self.state))
    }

    pub fn prepared_workspaces(&self) -> PreparedWorkspaceManager {
        PreparedWorkspaceManager::from_shared_state(Arc::clone(&self.state))
    }

    /// Retains a verified handle at the authoritative current generation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid bindings, unavailable native state, TTL, or capacity.
    pub fn issue(
        &self,
        window: &str,
        expected_generation: u64,
        request: &str,
        root: VerifiedRootHandle,
        now: Instant,
    ) -> Result<DirectorySelectionRef, SelectionError> {
        self.issue_inner(window, expected_generation, request, root, now, None)
    }

    /// Consumes only an entry matching the same authoritative generation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for expired, stale, invalid, or mismatched entries.
    pub fn consume(
        &self,
        reference: &DirectorySelectionRef,
        window: &str,
        expected_generation: u64,
        request: &str,
        now: Instant,
    ) -> Result<VerifiedRootHandle, SelectionError> {
        if !valid_binding(window) || !valid_binding(request) {
            return Err(SelectionError);
        }
        let mut state = self.state.lock().map_err(|_| SelectionError)?;
        let generation = state
            .existing_generation(window)
            .map_err(|_| SelectionError)?;
        let entry = state.selections.get(&reference.0).ok_or(SelectionError)?;
        if entry.expires_at <= now {
            state.selections.remove(&reference.0);
            return Err(SelectionError);
        }
        if generation != expected_generation
            || entry.window != window
            || entry.generation != generation
            || entry.request != request
        {
            return Err(SelectionError);
        }
        state
            .selections
            .remove(&reference.0)
            .map(|entry| entry.root)
            .ok_or(SelectionError)
    }

    fn issue_inner(
        &self,
        window: &str,
        expected_generation: u64,
        request: &str,
        root: VerifiedRootHandle,
        now: Instant,
        requested_reference: Option<String>,
    ) -> Result<DirectorySelectionRef, SelectionError> {
        if !valid_binding(window) || !valid_binding(request) {
            return Err(SelectionError);
        }
        let expires_at = now.checked_add(self.ttl).ok_or(SelectionError)?;
        let mut state = self.state.lock().map_err(|_| SelectionError)?;
        state.selections.retain(|_, entry| entry.expires_at > now);
        if state.selections.len() >= MAX_SELECTIONS {
            return Err(SelectionError);
        }
        let generation = state
            .existing_generation(window)
            .map_err(|_| SelectionError)?;
        if generation != expected_generation {
            return Err(SelectionError);
        }
        let mut root = Some(root);
        for reference in references(requested_reference) {
            if let Entry::Vacant(slot) = state.selections.entry(reference.clone()) {
                slot.insert(SelectionEntry {
                    window: window.to_owned(),
                    generation,
                    request: request.to_owned(),
                    root: root.take().ok_or(SelectionError)?,
                    expires_at,
                });
                return Ok(DirectorySelectionRef(reference));
            }
        }
        Err(SelectionError)
    }
}
impl fmt::Debug for DirectorySelectionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectorySelectionManager(<native-only>)")
    }
}
pub fn valid_binding(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BINDING_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn references(requested: Option<String>) -> impl Iterator<Item = String> {
    let mut values = Vec::with_capacity(4);
    if let Some(reference) = requested {
        if valid_reference(&reference) {
            values.push(reference);
        }
    } else {
        for _ in 0..4 {
            values.push(random_reference());
        }
    }
    values.into_iter()
}

pub fn random_reference() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn valid_reference(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
include!("directory_selection_parts/lifecycle.rs");
#[cfg(test)]
include!("directory_selection_parts/test_support.rs");

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    include!("directory_selection_parts/tests.rs");
}
