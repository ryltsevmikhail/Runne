struct SubscriptionState {
    cancelled: bool,
    in_flight: Option<u64>,
    last_acked: Option<u64>,
}

struct SubscriptionControl {
    state: Mutex<SubscriptionState>,
    changed: Notify,
}

impl SubscriptionControl {
    fn new() -> Self {
        Self {
            state: Mutex::new(SubscriptionState {
                cancelled: false,
                in_flight: None,
                last_acked: None,
            }),
            changed: Notify::new(),
        }
    }

    fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.cancelled = true;
        }
        self.changed.notify_one();
    }

    fn is_cancelled(&self) -> bool {
        self.state.lock().map_or(true, |state| state.cancelled)
    }

    fn set_in_flight(&self, revision: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.cancelled || state.in_flight.is_some() {
            return false;
        }
        state.in_flight = Some(revision);
        true
    }

    fn is_in_flight(&self, revision: u64) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.in_flight == Some(revision))
    }

    fn acknowledge(&self, revision: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let valid = !state.cancelled
            && state.in_flight == Some(revision)
            && state.last_acked.is_none_or(|last| revision > last);
        if valid {
            state.in_flight = None;
            state.last_acked = Some(revision);
        } else {
            state.cancelled = true;
        }
        drop(state);
        self.changed.notify_one();
        valid
    }
}
