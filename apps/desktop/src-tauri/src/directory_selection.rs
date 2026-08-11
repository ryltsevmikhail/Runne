use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use gocode_platform_desktop::VerifiedRootHandle;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_BINDING_BYTES: usize = 128;
const MAX_SELECTIONS: usize = 64;
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

struct SelectionEntry {
    window: String,
    generation: u64,
    request: String,
    root: VerifiedRootHandle,
    expires_at: Instant,
}

/// Native owner of directory handles selected by a renderer request.
pub struct DirectorySelectionManager {
    ttl: Duration,
    invalidated: AtomicBool,
    selections: Mutex<HashMap<String, SelectionEntry>>,
}

impl DirectorySelectionManager {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            invalidated: AtomicBool::new(false),
            selections: Mutex::new(HashMap::new()),
        }
    }

    /// Retains a verified native handle behind one random, bounded reference.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid bindings, expired TTLs, or capacity exhaustion.
    pub fn issue(
        &self,
        window: &str,
        generation: u64,
        request: &str,
        root: VerifiedRootHandle,
        now: Instant,
    ) -> Result<DirectorySelectionRef, SelectionError> {
        if !valid_binding(window)
            || !valid_binding(request)
            || self.ttl.is_zero()
            || self.ttl > MAX_SELECTION_TTL
        {
            return Err(SelectionError);
        }
        let expires_at = now.checked_add(self.ttl).ok_or(SelectionError)?;
        if self.invalidated.load(Ordering::Acquire) {
            return Err(SelectionError);
        }
        let mut selections = self.selections.lock().map_err(|_| SelectionError)?;
        selections.retain(|_, entry| entry.expires_at > now);
        if selections.len() >= MAX_SELECTIONS {
            return Err(SelectionError);
        }
        let mut root = Some(root);
        for _ in 0..4 {
            let reference = random_reference();
            if let Entry::Vacant(slot) = selections.entry(reference.clone()) {
                slot.insert(new_entry(
                    window,
                    generation,
                    request,
                    root.take().ok_or(SelectionError)?,
                    expires_at,
                ));
                return Ok(DirectorySelectionRef(reference));
            }
        }
        Err(SelectionError)
    }

    /// Consumes a matching reference exactly once and returns only its handle.
    ///
    /// # Errors
    ///
    /// Returns a closed error for expired, invalid, or mismatched bindings.
    pub fn consume(
        &self,
        reference: &DirectorySelectionRef,
        window: &str,
        generation: u64,
        request: &str,
        now: Instant,
    ) -> Result<VerifiedRootHandle, SelectionError> {
        if self.invalidated.load(Ordering::Acquire)
            || !valid_binding(window)
            || !valid_binding(request)
        {
            return Err(SelectionError);
        }
        let mut selections = self.selections.lock().map_err(|_| SelectionError)?;
        let entry = selections.get(&reference.0).ok_or(SelectionError)?;
        if entry.expires_at <= now {
            selections.remove(&reference.0);
            return Err(SelectionError);
        }
        if entry.window != window || entry.generation != generation || entry.request != request {
            return Err(SelectionError);
        }
        selections
            .remove(&reference.0)
            .map(|entry| entry.root)
            .ok_or(SelectionError)
    }

    /// Invalidates all pending selections for a destroyed or cancelled window.
    ///
    /// # Errors
    ///
    /// Returns a closed error and fences all selections if native state is poisoned.
    pub fn invalidate_window(&self, window: &str) -> Result<(), SelectionError> {
        if !valid_binding(window) {
            return Err(SelectionError);
        }
        self.selections
            .lock()
            .map_err(|_| {
                self.invalidated.store(true, Ordering::Release);
                SelectionError
            })?
            .retain(|_, entry| entry.window != window);
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[allow(clippy::too_many_arguments)]
    pub fn issue_with_reference_for_test(
        &self,
        window: &str,
        generation: u64,
        request: &str,
        root: VerifiedRootHandle,
        now: Instant,
        reference: String,
    ) -> Result<DirectorySelectionRef, SelectionError> {
        if self.invalidated.load(Ordering::Acquire)
            || !valid_binding(window)
            || !valid_binding(request)
            || self.ttl.is_zero()
            || self.ttl > MAX_SELECTION_TTL
        {
            return Err(SelectionError);
        }
        let reference = DirectorySelectionRef::parse(&reference)?;
        let expires_at = now.checked_add(self.ttl).ok_or(SelectionError)?;
        let mut selections = self.selections.lock().map_err(|_| SelectionError)?;
        if selections.len() >= MAX_SELECTIONS || selections.contains_key(&reference.0) {
            return Err(SelectionError);
        }
        selections.insert(
            reference.0.clone(),
            new_entry(window, generation, request, root, expires_at),
        );
        Ok(reference)
    }

    #[cfg(feature = "test-support")]
    pub fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lock = self.selections.lock().unwrap();
            panic!("test mutex poison");
        }));
    }
}

impl fmt::Debug for DirectorySelectionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectorySelectionManager")
            .field("selections", &"<native-only>")
            .finish()
    }
}

fn random_reference() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn valid_binding(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BINDING_BYTES
        && value.is_ascii()
        && !value.chars().any(char::is_control)
}

fn valid_reference(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn new_entry(
    window: &str,
    generation: u64,
    request: &str,
    root: VerifiedRootHandle,
    expires_at: Instant,
) -> SelectionEntry {
    SelectionEntry {
        window: window.to_owned(),
        generation,
        request: request.to_owned(),
        root,
        expires_at,
    }
}

#[cfg(test)]
mod tests {
    include!("directory_selection_parts/tests.rs");
}
