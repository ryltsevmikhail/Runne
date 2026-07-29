use std::collections::HashMap;

use gocode_domain::security::Generation;

#[derive(Debug, Clone)]
pub struct CleanupReservationRef {
    pub reservation_id: String,
    pub state: CleanupState,
    pub generation: Option<Generation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupState {
    Allocated,
    Attached,
    Released,
    UncertainHeld,
}

pub struct CleanupPool {
    capacity: usize,
    used: usize,
    reservations: HashMap<String, CleanupReservationRef>,
}

impl CleanupPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            used: 0,
            reservations: HashMap::new(),
        }
    }

    pub fn allocate(&mut self, id: String) -> Result<CleanupReservationRef, CleanupError> {
        self.allocate_inner(id, None)
    }

    pub fn allocate_for_generation(
        &mut self,
        id: String,
        generation: Generation,
    ) -> Result<CleanupReservationRef, CleanupError> {
        self.allocate_inner(id, Some(generation))
    }

    fn allocate_inner(
        &mut self,
        id: String,
        generation: Option<Generation>,
    ) -> Result<CleanupReservationRef, CleanupError> {
        if self.used >= self.capacity {
            return Err(CleanupError::CapacityUnavailable);
        }
        self.used += 1;
        let reservation = CleanupReservationRef {
            reservation_id: id,
            state: CleanupState::Allocated,
            generation,
        };
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        Ok(reservation)
    }

    pub fn release_activated(&mut self, id: &str) -> Result<(), CleanupError> {
        let reservation = self
            .reservations
            .get_mut(id)
            .ok_or(CleanupError::ReservationNotFound)?;
        if reservation.state == CleanupState::Released {
            return Ok(());
        }
        reservation.state = CleanupState::Released;
        self.used = self.used.saturating_sub(1);
        Ok(())
    }

    pub fn mark_uncertain(&mut self, id: &str) -> Result<(), CleanupError> {
        let reservation = self
            .reservations
            .get_mut(id)
            .ok_or(CleanupError::ReservationNotFound)?;
        reservation.state = CleanupState::UncertainHeld;
        Ok(())
    }

    pub fn release_for_generation(
        &mut self,
        id: &str,
        generation: Generation,
    ) -> Result<(), CleanupError> {
        let reservation = self
            .reservations
            .get(id)
            .ok_or(CleanupError::ReservationNotFound)?;
        if reservation.generation != Some(generation) {
            return Err(CleanupError::StaleGeneration);
        }
        self.release_activated(id)
    }

    pub fn reservation(&self, id: &str) -> Option<&CleanupReservationRef> {
        self.reservations.get(id)
    }

    pub fn available(&self) -> usize {
        self.capacity - self.used
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CleanupError {
    #[error("cleanup capacity unavailable")]
    CapacityUnavailable,
    #[error("reservation not found")]
    ReservationNotFound,
    #[error("cleanup generation is stale")]
    StaleGeneration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gocode_domain::security::Generation;

    #[test]
    fn capacity_exhausted() {
        let mut pool = CleanupPool::new(1);
        assert!(pool.allocate("r1".into()).is_ok());
        assert!(pool.allocate("r2".into()).is_err());
    }

    #[test]
    fn release_returns_capacity() {
        let mut pool = CleanupPool::new(2);
        pool.allocate("r1".into()).unwrap();
        assert_eq!(pool.available(), 1);
        pool.release_activated("r1").unwrap();
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn uncertain_holds_capacity() {
        let mut pool = CleanupPool::new(2);
        pool.allocate("r1".into()).unwrap();
        pool.mark_uncertain("r1").unwrap();
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn stale_generation_cannot_release_or_return_capacity() {
        let mut pool = CleanupPool::new(1);
        pool.allocate_for_generation("r1".into(), Generation::INITIAL)
            .unwrap();

        let result = pool.release_for_generation("r1", Generation::INITIAL.next());

        assert!(matches!(result, Err(CleanupError::StaleGeneration)));
        assert_eq!(pool.available(), 0);
        assert_eq!(
            pool.reservation("r1").unwrap().state,
            CleanupState::Allocated
        );
    }
}
