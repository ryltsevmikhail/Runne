use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use objc2::Message;
use objc2::rc::Retained;
use objc2_foundation::NSXPCConnection;

use super::super::SessionSlot;
use super::ConnectionGuard;

pub(super) struct ExpiryControl {
    cancelled: Mutex<bool>,
    wake: Condvar,
}

impl ExpiryControl {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: Mutex::new(false),
            wake: Condvar::new(),
        })
    }

    pub(super) fn cancel(&self) {
        *self
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_one();
    }

    #[allow(clippy::significant_drop_tightening)]
    fn wait_until(&self, deadline: Instant) -> bool {
        let mut cancelled = self
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if *cancelled {
                return false;
            }
            let duration = deadline.saturating_duration_since(Instant::now());
            if duration.is_zero() {
                return true;
            }
            let (next, _) = self
                .wake
                .wait_timeout(cancelled, duration)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cancelled = next;
        }
    }
}

struct TimerConnection(Retained<NSXPCConnection>);

// SAFETY: Foundation documents `NSXPCConnection` as thread-safe; timer only invalidates it.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for TimerConnection {}

impl TimerConnection {
    fn invalidate(self) {
        self.0.invalidate();
    }
}

pub(super) fn schedule(
    connection: &NSXPCConnection,
    slot: &SessionSlot,
    guard: &ConnectionGuard,
    control: &Arc<ExpiryControl>,
    deadline: Instant,
) -> bool {
    let connection = TimerConnection(connection.retain());
    let timer_slot = (*slot).clone();
    let timer_guard = (*guard).clone();
    let timer_control = Arc::clone(control);
    let spawned = std::thread::Builder::new()
        .name("runne-qualification-xpc-expiry".into())
        .spawn(move || {
            if timer_control.wait_until(deadline) {
                timer_slot.close();
                timer_guard.close();
                connection.invalidate();
            }
        })
        .is_ok();
    if !spawned {
        control.cancel();
        slot.close();
        guard.close();
    }
    spawned
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::ExpiryControl;

    #[test]
    fn repeated_early_wakes_do_not_skip_monotonic_expiry() {
        let control = ExpiryControl::new();
        let waiting = std::sync::Arc::clone(&control);
        let (sender, receiver) = mpsc::channel();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);
        std::thread::spawn(move || sender.send(waiting.wait_until(deadline)).unwrap());
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(1));
            control.wake.notify_one();
        }
        assert!(receiver.recv_timeout(Duration::from_millis(100)).unwrap());
        assert!(started.elapsed() >= Duration::from_millis(45));
    }

    #[test]
    fn cancellation_wakes_waiter_without_expiry() {
        let control = ExpiryControl::new();
        let waiting = std::sync::Arc::clone(&control);
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            sender
                .send(waiting.wait_until(Instant::now() + Duration::from_secs(1)))
                .unwrap();
        });
        control.cancel();
        assert!(!receiver.recv_timeout(Duration::from_millis(100)).unwrap());
    }
}
