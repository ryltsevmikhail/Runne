use crate::directory_selection::{valid_binding, valid_reference};
use rand::RngCore;
use runne_app_core::MutationAdmissionBinding;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::oneshot;

#[path = "destructive_intent/approval.rs"]
mod approval;
pub use approval::{ApprovalIntentId, ApprovalIntentManager};

const MAX_INTENTS: usize = 64;
const MAX_INTENT_TTL: Duration = Duration::from_secs(30);
#[derive(Clone)]
pub struct DestructiveIntentRef(String);
impl Serialize for DestructiveIntentRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for DestructiveIntentRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
impl DestructiveIntentRef {
    pub fn parse(value: &str) -> Result<Self, DestructiveIntentError> {
        valid_reference(value)
            .then(|| Self(value.into()))
            .ok_or(DestructiveIntentError)
    }
}
impl fmt::Debug for DestructiveIntentRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DestructiveIntentRef(<redacted>)")
    }
}
#[derive(Debug, Error)]
#[error("destructive intent rejected")]
pub struct DestructiveIntentError;
#[derive(Clone, Copy, Eq, PartialEq)]
enum LeaseState {
    Pending,
    Consumed,
    Committed,
    Cancelled,
}
struct Entry {
    window: String,
    generation: u64,
    binding: MutationAdmissionBinding,
    digest: [u8; 32],
    expires: Instant,
    state: LeaseState,
    decision: Option<oneshot::Sender<bool>>,
    completion: Option<oneshot::Sender<Result<(), ()>>>,
}
#[derive(Clone)]
pub struct DestructiveIntentManager {
    ttl: Duration,
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}
impl DestructiveIntentManager {
    pub fn new(ttl: Duration) -> Result<Self, DestructiveIntentError> {
        if ttl.is_zero() || ttl > MAX_INTENT_TTL {
            return Err(DestructiveIntentError);
        }
        Ok(Self {
            ttl,
            entries: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub fn issue(
        &self,
        window: &str,
        generation: u64,
        binding: MutationAdmissionBinding,
        digest: [u8; 32],
        now: Instant,
    ) -> Result<(DestructiveIntentRef, oneshot::Receiver<bool>), DestructiveIntentError> {
        if !valid_binding(window) {
            return Err(DestructiveIntentError);
        }
        let expires = now.checked_add(self.ttl).ok_or(DestructiveIntentError)?;
        let mut entries = self.entries.lock().map_err(|_| DestructiveIntentError)?;
        entries.retain(|_, e| e.state == LeaseState::Committed || e.expires > now);
        if entries.len() >= MAX_INTENTS {
            return Err(DestructiveIntentError);
        }
        let (decision, decision_rx) = oneshot::channel();
        for _ in 0..4 {
            let key = random_reference();
            if entries.contains_key(&key) {
                continue;
            }
            entries.insert(
                key.clone(),
                Entry {
                    window: window.into(),
                    generation,
                    binding,
                    digest,
                    expires,
                    state: LeaseState::Pending,
                    decision: Some(decision),
                    completion: None,
                },
            );
            drop(entries);
            return Ok((DestructiveIntentRef(key), decision_rx));
        }
        Err(DestructiveIntentError)
    }
    pub fn consume(
        &self,
        reference: &DestructiveIntentRef,
        window: &str,
        generation: u64,
        now: Instant,
    ) -> Result<oneshot::Receiver<Result<(), ()>>, DestructiveIntentError> {
        let mut entries = self.entries.lock().map_err(|_| DestructiveIntentError)?;
        let decision = {
            let entry = entries
                .get_mut(&reference.0)
                .ok_or(DestructiveIntentError)?;
            if entry.expires <= now
                || entry.window != window
                || entry.generation != generation
                || entry.state != LeaseState::Pending
            {
                return Err(DestructiveIntentError);
            }
            entry.decision.take().ok_or(DestructiveIntentError)?
        };
        if decision.send(true).is_err() {
            entries.remove(&reference.0);
            return Err(DestructiveIntentError);
        }
        let (sender, receiver) = oneshot::channel();
        let entry = entries
            .get_mut(&reference.0)
            .ok_or(DestructiveIntentError)?;
        entry.state = LeaseState::Consumed;
        entry.completion = Some(sender);
        drop(entries);
        Ok(receiver)
    }
    pub fn try_commit(
        &self,
        reference: &DestructiveIntentRef,
        binding: MutationAdmissionBinding,
        digest: [u8; 32],
        now: Instant,
    ) -> bool {
        self.entries
            .lock()
            .ok()
            .and_then(|mut entries| {
                entries.get_mut(&reference.0).and_then(|entry| {
                    (entry.state == LeaseState::Consumed
                        && entry.binding == binding
                        && entry.digest == digest
                        && entry.expires > now)
                        .then(|| {
                            entry.state = LeaseState::Committed;
                            true
                        })
                })
            })
            .unwrap_or(false)
    }
    pub fn finish(&self, reference: &DestructiveIntentRef, result: Result<(), ()>) {
        if let Ok(mut entries) = self.entries.lock()
            && let Some(mut entry) = entries.remove(&reference.0)
            && let Some(sender) = entry.completion.take()
        {
            let _ = sender.send(result);
        }
    }
    pub fn invalidate_window(&self, window: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, e| cancel(e, e.window == window));
        }
    }
    pub fn clear_pending(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, e| cancel(e, true));
        }
    }
}
fn cancel(entry: &mut Entry, selected: bool) -> bool {
    if !selected || entry.state == LeaseState::Committed {
        return true;
    }
    entry.state = LeaseState::Cancelled;
    if let Some(sender) = entry.decision.take() {
        let _ = sender.send(false);
    }
    if let Some(sender) = entry.completion.take() {
        let _ = sender.send(Err(()));
    }
    false
}
impl fmt::Debug for DestructiveIntentManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DestructiveIntentManager(<native-only>)")
    }
}
fn random_reference() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
#[cfg(test)]
mod tests {
    include!("destructive_intent_parts/tests.rs");
}

#[cfg(test)]
mod approval_intent_tests;
