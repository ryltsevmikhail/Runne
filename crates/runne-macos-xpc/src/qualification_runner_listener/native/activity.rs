use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

pub(super) const MAX_ACTIVE_QUALIFICATION_SESSIONS: usize = 16;

#[derive(Clone)]
pub(super) struct ConnectionActivity(Arc<AtomicUsize>);

impl ConnectionActivity {
    pub(super) fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }

    pub(super) fn try_open(&self) -> Option<ConnectionGuard> {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_ACTIVE_QUALIFICATION_SESSIONS).then_some(active + 1)
            })
            .ok()
            .map(|_| ConnectionGuard {
                activity: self.clone(),
                state: Arc::new(Mutex::new(GuardState::default())),
            })
    }

    fn release(&self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Default)]
struct GuardState {
    closing: bool,
    in_flight: usize,
    released: bool,
}

#[derive(Clone)]
pub(super) struct ConnectionGuard {
    activity: ConnectionActivity,
    state: Arc<Mutex<GuardState>>,
}

impl ConnectionGuard {
    pub(super) fn enter(&self) -> Option<ConnectionCallGuard> {
        {
            let mut state = self.lock();
            if state.closing {
                return None;
            }
            state.in_flight += 1;
        }
        Some(ConnectionCallGuard(self.clone()))
    }

    pub(super) fn close(&self) {
        let release = {
            let mut state = self.lock();
            state.closing = true;
            state.in_flight == 0 && !std::mem::replace(&mut state.released, true)
        };
        if release {
            self.activity.release();
        }
    }

    fn leave(&self) {
        let release = {
            let mut state = self.lock();
            state.in_flight -= 1;
            state.closing && state.in_flight == 0 && !std::mem::replace(&mut state.released, true)
        };
        if release {
            self.activity.release();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GuardState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(super) struct ConnectionCallGuard(ConnectionGuard);

impl Drop for ConnectionCallGuard {
    fn drop(&mut self) {
        self.0.leave();
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionActivity, MAX_ACTIVE_QUALIFICATION_SESSIONS};

    #[test]
    fn capacity_stays_reserved_until_blocked_calls_return() {
        let activity = ConnectionActivity::new();
        let guards = (0..MAX_ACTIVE_QUALIFICATION_SESSIONS)
            .map(|_| activity.try_open().expect("capacity available"))
            .collect::<Vec<_>>();
        let calls = guards
            .iter()
            .map(|guard| guard.enter().expect("connection open"))
            .collect::<Vec<_>>();
        for guard in &guards {
            guard.close();
        }
        assert!(activity.try_open().is_none());
        drop(calls);
        assert!(activity.try_open().is_some());
    }
}
