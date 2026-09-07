//! Reservation ledger (Plan Task 12): capacity across all quote
//! dimensions is reserved BEFORE host load/generate, committed on
//! dispatch and released only on proven terminal cleanup. Reservations
//! carry a fencing token; stale or fence-mismatched operations refuse.
//! Exactly one loaded model exists; conflicting reservations are
//! refused, never silently evicted.

use crate::resource_quote::LocalResourceQuote;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationError {
    /// A reservation already exists for the attempt.
    DuplicateAttempt,
    /// Another model is loaded; no implicit eviction.
    OneLoadedModelConflict,
    /// The reservation expired before it was committed.
    StaleReservation,
    /// Fencing token does not match the reservation.
    FenceMismatch,
    /// RAM capacity of the profile is exhausted.
    CapacityExhausted,
    /// The attempt is frozen (conflicting settlement) and accepts no
    /// further ledger operations.
    AttemptFrozen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fence(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Reservation {
    attempt_id: [u8; 16],
    model_identity: String,
    quote: LocalResourceQuote,
    fence: Fence,
    reserved_at: Instant,
    committed: bool,
    released: bool,
}

/// Profile capacity envelope the ledger enforces across reservations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    pub total_ram_bytes: u64,
    pub reservation_ttl: Duration,
}

#[derive(Debug)]
pub struct ReservationLedger {
    capacity: Capacity,
    reserved_ram: u64,
    loaded_model: Option<String>,
    reservations: std::collections::BTreeMap<[u8; 16], Reservation>,
    frozen: BTreeSet<[u8; 16]>,
    next_fence: u64,
}

impl ReservationLedger {
    pub fn new(capacity: Capacity) -> Self {
        Self {
            capacity,
            reserved_ram: 0,
            loaded_model: None,
            reservations: std::collections::BTreeMap::new(),
            frozen: BTreeSet::new(),
            next_fence: 1,
        }
    }

    pub fn is_frozen(&self, attempt_id: &[u8; 16]) -> bool {
        self.frozen.contains(attempt_id)
    }

    /// Freezes an attempt (conflicting/unavailable settlement): no
    /// further reservations or commits accept it.
    pub fn freeze(&mut self, attempt_id: [u8; 16]) {
        self.frozen.insert(attempt_id);
    }

    pub fn loaded_model(&self) -> Option<&str> {
        self.loaded_model.as_deref()
    }

    /// True when no reservations are held (idle-unload precondition).
    pub fn reservations_empty(&self) -> bool {
        self.reservations.is_empty()
    }

    /// Reserves the quote dimensions for one attempt under a fresh
    /// fencing token.
    pub fn reserve(
        &mut self,
        attempt_id: [u8; 16],
        model_identity: &str,
        quote: &LocalResourceQuote,
        now: Instant,
    ) -> Result<Fence, ReservationError> {
        if self.frozen.contains(&attempt_id) {
            return Err(ReservationError::AttemptFrozen);
        }
        if self.reservations.contains_key(&attempt_id) {
            return Err(ReservationError::DuplicateAttempt);
        }
        if let Some(loaded) = &self.loaded_model
            && loaded != model_identity
        {
            return Err(ReservationError::OneLoadedModelConflict);
        }
        let ram = self
            .reserved_ram
            .checked_add(quote.ram_bytes)
            .ok_or(ReservationError::CapacityExhausted)?;
        if ram > self.capacity.total_ram_bytes {
            return Err(ReservationError::CapacityExhausted);
        }
        let fence = Fence(self.next_fence);
        self.next_fence += 1;
        self.reservations.insert(
            attempt_id,
            Reservation {
                attempt_id,
                model_identity: model_identity.to_string(),
                quote: quote.clone(),
                fence,
                reserved_at: now,
                committed: false,
                released: false,
            },
        );
        self.reserved_ram = ram;
        Ok(fence)
    }

    /// Commits the reservation (dispatch admitted) under the exact
    /// fence; marks the model loaded.
    pub fn commit(
        &mut self,
        attempt_id: &[u8; 16],
        fence: Fence,
        now: Instant,
    ) -> Result<(), ReservationError> {
        let r = self
            .reservations
            .get_mut(attempt_id)
            .ok_or(ReservationError::StaleReservation)?;
        if r.fence != fence {
            return Err(ReservationError::FenceMismatch);
        }
        if now.duration_since(r.reserved_at) > self.capacity.reservation_ttl {
            return Err(ReservationError::StaleReservation);
        }
        if r.committed {
            return Err(ReservationError::StaleReservation);
        }
        r.committed = true;
        if self.loaded_model.is_none() {
            self.loaded_model = Some(r.model_identity.clone());
        }
        Ok(())
    }

    /// Releases a terminal attempt's reservation; capacity returns
    /// only on this proven release (never on estimates).
    pub fn release(&mut self, attempt_id: &[u8; 16], fence: Fence) -> Result<(), ReservationError> {
        let Some(r) = self.reservations.remove(attempt_id) else {
            return Err(ReservationError::StaleReservation);
        };
        if r.fence != fence {
            // Put it back: a bad fence must not consume the record.
            self.reservations.insert(*attempt_id, r);
            return Err(ReservationError::FenceMismatch);
        }
        self.reserved_ram = self.reserved_ram.saturating_sub(r.quote.ram_bytes);
        if self.reservations.is_empty() {
            self.loaded_model = None;
        }
        Ok(())
    }

    /// Drops stale uncommitted reservations (housekeeping sweep).
    pub fn sweep_stale(&mut self, now: Instant) -> usize {
        let stale: Vec<[u8; 16]> = self
            .reservations
            .iter()
            .filter(|(_, r)| {
                !r.committed && now.duration_since(r.reserved_at) > self.capacity.reservation_ttl
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            if let Some(r) = self.reservations.remove(id) {
                self.reserved_ram = self.reserved_ram.saturating_sub(r.quote.ram_bytes);
            }
        }
        if self.reservations.is_empty() {
            self.loaded_model = None;
        }
        stale.len()
    }
}
