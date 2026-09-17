use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use objc2::Message;
use objc2::rc::Retained;
use objc2_foundation::NSXPCConnection;

use crate::qualification_runner_listener::SessionSlot;

use super::activity::ConnectionGuard;
use super::timer::ExpiryControl;

pub(super) struct AcceptedRegistry {
    admission: AdmissionGate,
    accepted: Mutex<Vec<AcceptedConnection>>,
}

struct AdmissionGate(AtomicBool);

impl AdmissionGate {
    const fn new() -> Self {
        Self(AtomicBool::new(true))
    }

    fn begin_insert(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn finish_insert(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn close(&self) {
        self.0.store(false, Ordering::Release);
    }
}

struct AcceptedConnection {
    slot: SessionSlot,
    guard: ConnectionGuard,
    control: std::sync::Arc<ExpiryControl>,
    connection: Retained<NSXPCConnection>,
}

impl AcceptedRegistry {
    pub(super) const fn new() -> Self {
        Self {
            admission: AdmissionGate::new(),
            accepted: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn insert(
        &self,
        slot: SessionSlot,
        guard: ConnectionGuard,
        control: std::sync::Arc<ExpiryControl>,
        connection: &NSXPCConnection,
    ) -> bool {
        if !self.admission.begin_insert() {
            return false;
        }
        let mut accepted = self.lock();
        accepted.retain(|entry| !entry.slot.is_closed());
        if !self.admission.finish_insert() {
            return false;
        }
        accepted.push(AcceptedConnection {
            slot,
            guard,
            control,
            connection: connection.retain(),
        });
        true
    }

    pub(super) fn close_all(&self) {
        self.admission.close();
        for entry in self.lock().iter() {
            entry.control.cancel();
            entry.slot.close();
            entry.guard.close();
            entry.connection.invalidate();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<AcceptedConnection>> {
        self.accepted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::AdmissionGate;

    #[test]
    fn close_between_insert_checks_prevents_late_admission() {
        let gate = AdmissionGate::new();
        assert!(gate.begin_insert());
        gate.close();
        assert!(!gate.finish_insert());
    }
}
