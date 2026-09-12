use std::sync::{Condvar, Mutex};
use std::time::Instant;

use runne_api::{
    BootstrapAck, DesktopOffer, DesktopOfferRequest, RootPrepared, RunBinding,
    RuntimeBootstrapRequest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
    Rejected,
}

pub struct RunCoordinator {
    prepared: RootPrepared,
    deadline: Instant,
    phase: Mutex<Phase>,
    changed: Condvar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Opening,
    DesktopReserved,
    AwaitingDesktop,
    DesktopSession,
    Offered,
    RuntimeSession,
    AckPendingDelivery,
    Terminal,
}

pub struct RuntimeTicket {
    offer_id: [u8; 32],
    binding: RunBinding,
    run_not_after: u64,
    deadline: Instant,
}

impl RunCoordinator {
    pub(crate) const fn new(prepared: RootPrepared, deadline: Instant) -> Self {
        Self {
            prepared,
            deadline,
            phase: Mutex::new(Phase::Opening),
            changed: Condvar::new(),
        }
    }

    pub(crate) const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn opened(&self) -> Result<(), CoordinatorError> {
        let mut phase = self.lock();
        let next = match *phase {
            Phase::Opening => Phase::AwaitingDesktop,
            Phase::DesktopReserved => Phase::DesktopSession,
            _ => {
                *phase = Phase::Terminal;
                drop(phase);
                self.changed.notify_all();
                return Err(CoordinatorError::Rejected);
            }
        };
        *phase = next;
        drop(phase);
        self.changed.notify_all();
        Ok(())
    }

    pub(crate) fn fail(&self) {
        let mut phase = self.lock();
        let notify = if *phase == Phase::AckPendingDelivery {
            false
        } else {
            *phase = Phase::Terminal;
            true
        };
        drop(phase);
        if notify {
            self.changed.notify_all();
        }
    }

    pub(crate) fn claim_desktop(&self) -> Result<(), CoordinatorError> {
        let mut phase = self.lock();
        match *phase {
            Phase::Opening => *phase = Phase::DesktopReserved,
            Phase::AwaitingDesktop => *phase = Phase::DesktopSession,
            _ => {
                *phase = Phase::Terminal;
                drop(phase);
                self.changed.notify_all();
                return Err(CoordinatorError::Rejected);
            }
        }
        drop(phase);
        self.changed.notify_all();
        Ok(())
    }

    pub(crate) fn desktop_offer(
        &self,
        request: &DesktopOfferRequest,
    ) -> Result<DesktopOffer, CoordinatorError> {
        self.wait_desktop_open()?;
        DesktopOffer::new(
            request.desktop_challenge(),
            self.prepared.offer_id(),
            duplicate_binding(self.prepared.binding())?,
            self.prepared.expires_at(),
            self.prepared.run_not_after(),
        )
        .map_err(|_| CoordinatorError::Rejected)
    }

    pub(crate) fn finish_desktop(&self) -> Result<(), CoordinatorError> {
        self.transition(Phase::DesktopSession, Phase::Offered)
    }

    pub(crate) fn claim_runtime(&self) -> Result<RuntimeTicket, CoordinatorError> {
        self.transition_runtime()?;
        Ok(RuntimeTicket {
            offer_id: self.prepared.offer_id(),
            binding: duplicate_binding(self.prepared.binding())?,
            run_not_after: self.prepared.run_not_after(),
            deadline: self.deadline,
        })
    }

    pub(crate) fn validate_runtime(
        &self,
        ticket: &RuntimeTicket,
        ack: &BootstrapAck,
    ) -> Result<(), CoordinatorError> {
        self.active(Phase::RuntimeSession)?;
        (ack.offer_id() == ticket.offer_id
            && ack.daemon_challenge() != [0; 32]
            && same_binding(ack.binding(), &ticket.binding)
            && ack.proof_sha256() != [0; 32]
            && ack.run_not_after() == ticket.run_not_after)
            .then_some(())
            .ok_or(CoordinatorError::Rejected)?;
        Ok(())
    }

    pub(crate) fn finish_runtime(&self) -> Result<(), CoordinatorError> {
        self.transition(Phase::RuntimeSession, Phase::AckPendingDelivery)
    }

    /// Keeps listeners alive after an internal root acknowledgement, because the
    /// native callback has not necessarily delivered the runtime reply yet.
    pub(crate) fn wait_until_deadline_or_terminal(&self) {
        let mut phase = self.lock();
        loop {
            if *phase == Phase::Terminal || Instant::now() >= self.deadline {
                return;
            }
            let timeout = self.deadline.saturating_duration_since(Instant::now());
            let (next, _) = self
                .changed
                .wait_timeout(phase, timeout)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            phase = next;
        }
    }

    fn wait_desktop_open(&self) -> Result<(), CoordinatorError> {
        let mut phase = self.lock();
        while *phase == Phase::DesktopReserved && Instant::now() < self.deadline {
            let timeout = self.deadline.saturating_duration_since(Instant::now());
            let (next, _) = self
                .changed
                .wait_timeout(phase, timeout)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            phase = next;
        }
        (*phase == Phase::DesktopSession)
            .then_some(())
            .ok_or(CoordinatorError::Rejected)
    }

    fn transition_runtime(&self) -> Result<(), CoordinatorError> {
        let mut phase = self.lock();
        if Instant::now() >= self.deadline {
            *phase = Phase::Terminal;
            drop(phase);
            self.changed.notify_all();
            return Err(CoordinatorError::Rejected);
        }
        if *phase != Phase::Offered {
            return Err(CoordinatorError::Rejected);
        }
        *phase = Phase::RuntimeSession;
        drop(phase);
        self.changed.notify_all();
        Ok(())
    }

    fn active(&self, expected: Phase) -> Result<(), CoordinatorError> {
        (Instant::now() < self.deadline && *self.lock() == expected)
            .then_some(())
            .ok_or(CoordinatorError::Rejected)
    }

    fn transition(&self, expected: Phase, next: Phase) -> Result<(), CoordinatorError> {
        let mut phase = self.lock();
        if Instant::now() >= self.deadline || *phase != expected {
            *phase = Phase::Terminal;
            drop(phase);
            self.changed.notify_all();
            return Err(CoordinatorError::Rejected);
        }
        *phase = next;
        drop(phase);
        self.changed.notify_all();
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Phase> {
        self.phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl RuntimeTicket {
    pub(crate) const fn offer_id(&self) -> [u8; 32] {
        self.offer_id
    }

    pub(crate) const fn binding(&self) -> &RunBinding {
        &self.binding
    }

    pub(crate) const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn duplicate(&self) -> Result<Self, CoordinatorError> {
        Ok(Self {
            offer_id: self.offer_id,
            binding: duplicate_binding(&self.binding)?,
            run_not_after: self.run_not_after,
            deadline: self.deadline,
        })
    }

    pub(crate) const fn run_not_after(&self) -> u64 {
        self.run_not_after
    }

    pub(crate) fn matches(&self, request: &RuntimeBootstrapRequest) -> bool {
        request.offer_id() == self.offer_id
            && request.candidate_sha256() == self.binding.candidate_sha256()
            && request.raw_v3_tuple_sha256() == self.binding.raw_v3_tuple_sha256()
            && request.profile_sha256() == self.binding.profile_sha256()
    }
}

pub fn duplicate_binding(value: &RunBinding) -> Result<RunBinding, CoordinatorError> {
    RunBinding::new(
        value.workflow_run_id(),
        value.source_revision(),
        value.candidate_sha256(),
        value.raw_v3_tuple_sha256(),
        value.namespace_sha256(),
        value.manifest_sha256(),
        value.profile_sha256(),
    )
    .map_err(|_| CoordinatorError::Rejected)
}

pub fn same_binding(left: &RunBinding, right: &RunBinding) -> bool {
    left.workflow_run_id() == right.workflow_run_id()
        && left.source_revision() == right.source_revision()
        && left.candidate_sha256() == right.candidate_sha256()
        && left.raw_v3_tuple_sha256() == right.raw_v3_tuple_sha256()
        && left.namespace_sha256() == right.namespace_sha256()
        && left.manifest_sha256() == right.manifest_sha256()
        && left.profile_sha256() == right.profile_sha256()
}

#[cfg(test)]
#[path = "coordinator/tests.rs"]
mod tests;
