use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use super::{MAX_SELECTIONS, SelectionError, valid_binding};

pub(super) struct PickerReservationState {
    pending: Arc<Mutex<HashSet<String>>>,
}

impl PickerReservationState {
    pub(super) fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    #[cfg(test)]
    fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lock = self.pending.lock().expect("picker lock");
            panic!("test picker mutex poison");
        }));
    }
}

/// Move-only reservation for one outstanding native directory picker.
pub struct PickerReservationLease {
    pending: Arc<Mutex<HashSet<String>>>,
    window: Option<String>,
}

impl PickerReservationLease {
    #[allow(
        clippy::significant_drop_tightening,
        reason = "retain the pending lock until the reservation lease is fully constructed"
    )]
    pub(super) fn reserve(
        state: &PickerReservationState,
        window: &str,
    ) -> Result<Self, SelectionError> {
        if !valid_binding(window) {
            return Err(SelectionError);
        }
        let mut pending = state.pending.lock().map_err(|_| SelectionError)?;
        if pending.contains(window) || pending.len() >= MAX_SELECTIONS {
            return Err(SelectionError);
        }
        if !pending.insert(window.to_owned()) {
            return Err(SelectionError);
        }
        Ok(Self {
            pending: Arc::clone(&state.pending),
            window: Some(window.to_owned()),
        })
    }
}

impl Drop for PickerReservationLease {
    fn drop(&mut self) {
        let Some(window) = self.window.take() else {
            return;
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&window);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use super::*;
    use crate::directory_selection::DirectorySelectionManager;

    fn manager() -> DirectorySelectionManager {
        DirectorySelectionManager::new(Duration::from_secs(1)).expect("manager")
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "keep the manager alive for the complete reservation lifetime assertion"
    )]
    fn duplicate_picker_is_rejected_until_the_first_dialog_lease_drops() {
        let manager = manager();
        assert_eq!(
            manager.renderer_generations().page_loaded("main").unwrap(),
            1
        );
        let first = manager.reserve_picker("main", 1).expect("first lease");
        assert!(manager.reserve_picker("main", 1).is_err());
        drop(first);
        assert!(manager.reserve_picker("main", 1).is_ok());
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "keep the manager alive for the complete reservation lifetime assertion"
    )]
    fn newer_generation_cannot_open_a_second_picker_before_dialog_close() {
        let manager = manager();
        assert_eq!(
            manager.renderer_generations().page_loaded("main").unwrap(),
            1
        );
        let first = manager.reserve_picker("main", 1).expect("first lease");
        assert_eq!(
            manager.renderer_generations().page_loaded("main").unwrap(),
            2
        );
        assert!(manager.reserve_picker("main", 2).is_err());
        drop(first);
        assert!(manager.reserve_picker("main", 2).is_ok());
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "keep the manager alive for the complete reservation lifetime assertion"
    )]
    fn stale_generation_is_rejected_before_picker_reservation() {
        let manager = manager();
        assert_eq!(
            manager.renderer_generations().page_loaded("main").unwrap(),
            1
        );
        assert!(manager.reserve_picker("main", 2).is_err());
        assert!(manager.reserve_picker("main", 1).is_ok());
    }

    #[test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "keep the manager alive for the complete reservation lifetime assertion"
    )]
    fn independent_windows_can_each_hold_one_picker() {
        let manager = manager();
        assert_eq!(
            manager.renderer_generations().page_loaded("main").unwrap(),
            1
        );
        assert_eq!(
            manager
                .renderer_generations()
                .page_loaded("settings")
                .unwrap(),
            1
        );
        let main = manager.reserve_picker("main", 1).expect("main lease");
        let settings = manager
            .reserve_picker("settings", 1)
            .expect("settings lease");
        drop((main, settings));
    }

    #[test]
    fn concurrent_requests_for_the_same_window_have_one_winner() {
        let manager = Arc::new(manager());
        assert_eq!(
            manager.renderer_generations().page_loaded("main").unwrap(),
            1
        );
        let barrier = Arc::new(Barrier::new(2));
        let spawn = || {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let lease = manager.reserve_picker("main", 1);
                barrier.wait();
                lease.is_ok()
            })
        };
        let threads = [spawn(), spawn()];
        let winners = threads
            .into_iter()
            .map(|thread| thread.join().expect("picker worker"))
            .filter(|winner| *winner)
            .count();
        assert_eq!(winners, 1);
    }

    #[test]
    fn picker_capacity_is_bounded() {
        let state = PickerReservationState::new();
        let leases = (0..MAX_SELECTIONS)
            .map(|index| PickerReservationLease::reserve(&state, &format!("window-{index}")))
            .collect::<Result<Vec<_>, _>>()
            .expect("bounded leases");
        assert!(PickerReservationLease::reserve(&state, "overflow").is_err());
        drop(leases);
    }

    #[test]
    fn poisoned_picker_state_fails_closed() {
        let state = PickerReservationState::new();
        state.poison_for_test();
        assert!(PickerReservationLease::reserve(&state, "main").is_err());
    }
}
