use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rand::RngCore;
use runne_app_core::ApprovalConfirmationBinding;
use serde::{Deserialize, Serialize};

use super::{DestructiveIntentError, MAX_INTENT_TTL, MAX_INTENTS, valid_binding};

/// Opaque, single-use renderer handle for a host-owned approval confirmation.
#[derive(Clone)]
pub struct ApprovalIntentId(String);

impl Serialize for ApprovalIntentId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ApprovalIntentId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        (value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        .then_some(Self(value))
        .ok_or_else(|| serde::de::Error::custom("invalid approval intent"))
    }
}

impl std::fmt::Debug for ApprovalIntentId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApprovalIntentId(<redacted>)")
    }
}

struct ApprovalEntry {
    window: String,
    generation: u64,
    binding: ApprovalConfirmationBinding,
    expires_at_ms: u64,
    deadline: Instant,
}

/// Holds bounded approval confirmations until their sole consume attempt.
#[derive(Clone)]
pub struct ApprovalIntentManager {
    ttl: Duration,
    entries: Arc<Mutex<HashMap<String, ApprovalEntry>>>,
}

impl ApprovalIntentManager {
    pub fn new(ttl: Duration) -> Result<Self, DestructiveIntentError> {
        if ttl.is_zero() || ttl > MAX_INTENT_TTL {
            return Err(DestructiveIntentError);
        }
        Ok(Self {
            ttl,
            entries: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn prepare(
        &self,
        window: &str,
        generation: u64,
        binding: ApprovalConfirmationBinding,
        now: SystemTime,
    ) -> Result<ApprovalIntentId, DestructiveIntentError> {
        self.prepare_with_clock(window, generation, binding, now, Instant::now())
    }

    /// Creates an intent using an explicit wall and monotonic clock snapshot.
    pub fn prepare_with_clock(
        &self,
        window: &str,
        generation: u64,
        binding: ApprovalConfirmationBinding,
        now: SystemTime,
        monotonic_now: Instant,
    ) -> Result<ApprovalIntentId, DestructiveIntentError> {
        if !valid_binding(window) {
            return Err(DestructiveIntentError);
        }
        let (expires_at_ms, deadline) =
            intent_expiry(binding.expires_at(), self.ttl, now, monotonic_now)
                .ok_or(DestructiveIntentError)?;
        let mut entries = self.entries.lock().map_err(|_| DestructiveIntentError)?;
        entries.retain(|_, entry| unexpired(entry, now, monotonic_now));
        if entries.values().any(|entry| entry.window == window) || entries.len() >= MAX_INTENTS {
            return Err(DestructiveIntentError);
        }
        for _ in 0..4 {
            let id = random_id();
            if entries.contains_key(&id) {
                continue;
            }
            entries.insert(
                id.clone(),
                ApprovalEntry {
                    window: window.into(),
                    generation,
                    binding,
                    expires_at_ms,
                    deadline,
                },
            );
            let intent = ApprovalIntentId(id);
            drop(entries);
            return Ok(intent);
        }
        drop(entries);
        Err(DestructiveIntentError)
    }

    pub fn consume(
        &self,
        id: &ApprovalIntentId,
        window: &str,
        generation: u64,
        binding: &ApprovalConfirmationBinding,
        now: SystemTime,
    ) -> Result<ApprovalConfirmationBinding, DestructiveIntentError> {
        self.consume_with_clock(id, window, generation, binding, now, Instant::now())
    }

    /// Consumes an intent only when its wall and monotonic deadlines remain valid.
    pub fn consume_with_clock(
        &self,
        id: &ApprovalIntentId,
        window: &str,
        generation: u64,
        binding: &ApprovalConfirmationBinding,
        now: SystemTime,
        monotonic_now: Instant,
    ) -> Result<ApprovalConfirmationBinding, DestructiveIntentError> {
        let entry = self
            .entries
            .lock()
            .map_err(|_| DestructiveIntentError)?
            .remove(&id.0);
        let Some(entry) = entry else {
            return Err(DestructiveIntentError);
        };
        if entry.window != window
            || entry.generation != generation
            || !unexpired(&entry, now, monotonic_now)
            || !entry.binding.matches(binding)
        {
            return Err(DestructiveIntentError);
        }
        Ok(entry.binding)
    }

    pub fn invalidate_window(&self, window: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, entry| entry.window != window);
        }
    }
    pub fn clear_pending(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

fn intent_expiry(
    expires_at: i64,
    ttl: Duration,
    now: SystemTime,
    monotonic_now: Instant,
) -> Option<(u64, Instant)> {
    let Ok(now) = now.duration_since(UNIX_EPOCH) else {
        return None;
    };
    let now_ms = u64::try_from(now.as_millis()).ok()?;
    let ttl_ms = u64::try_from(ttl.as_millis()).ok()?;
    let Ok(expires_at) = u64::try_from(expires_at) else {
        return None;
    };
    if expires_at <= now_ms {
        return None;
    }
    let remaining_ms = expires_at.checked_sub(now_ms)?.min(ttl_ms);
    let deadline = monotonic_now.checked_add(Duration::from_millis(remaining_ms))?;
    Some((expires_at, deadline))
}

fn unexpired(entry: &ApprovalEntry, now: SystemTime, monotonic_now: Instant) -> bool {
    now.duration_since(UNIX_EPOCH).is_ok_and(|value| {
        u64::try_from(value.as_millis()).is_ok_and(|now_ms| entry.expires_at_ms > now_ms)
    }) && entry.deadline > monotonic_now
}

fn random_id() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
