use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use crate::qualification_runner::{
    QualificationRunnerEndpointConfiguration, QualificationRunnerPeer, QualificationRunnerRequest,
    QualificationRunnerSessionFactory, QualificationRunnerSessionReceipt,
    QualificationRunnerXpcError,
};

#[cfg(target_os = "macos")]
mod native;

/// Separate qualification listener. Every accepted connection receives one new session.
pub struct QualificationRunnerXpcListener {
    #[cfg(target_os = "macos")]
    native: native::NativeQualificationRunnerListener,
}

impl QualificationRunnerXpcListener {
    /// Binds one fixed endpoint after pinning its client requirement.
    ///
    /// # Errors
    ///
    /// Fails closed outside macOS or when Foundation rejects the configuration.
    pub fn bind(
        configuration: &QualificationRunnerEndpointConfiguration,
        factory: Arc<dyn QualificationRunnerSessionFactory>,
    ) -> Result<Self, QualificationRunnerXpcError> {
        #[cfg(target_os = "macos")]
        {
            native::NativeQualificationRunnerListener::bind(configuration, factory)
                .map(|native| Self { native })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (configuration, factory);
            Err(QualificationRunnerXpcError::Unsupported)
        }
    }

    /// Stops the listener and terminates all subsequently accepted sessions.
    #[cfg(target_os = "macos")]
    pub fn invalidate(&self) {
        self.native.invalidate();
    }

    #[cfg(not(target_os = "macos"))]
    pub const fn invalidate(&self) {
        let _ = self;
    }
}

#[derive(Clone)]
pub struct SessionSlot {
    session: Arc<Mutex<Option<crate::QualificationRunnerSessionLease>>>,
    terminal: Arc<AtomicBool>,
    in_flight: Arc<AtomicBool>,
}

struct SessionFlight<'a>(&'a SessionSlot);

impl Drop for SessionFlight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.store(false, Ordering::Release);
        self.0.dispose_terminal();
    }
}

impl SessionSlot {
    pub(crate) fn new(session: crate::QualificationRunnerSessionLease) -> Self {
        Self {
            session: Arc::new(Mutex::new(Some(session))),
            terminal: Arc::new(AtomicBool::new(false)),
            in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    #[allow(clippy::significant_drop_tightening)]
    pub(crate) fn exchange(
        &self,
        request: QualificationRunnerRequest,
    ) -> Result<crate::qualification_runner::QualificationRunnerReply, QualificationRunnerXpcError>
    {
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(QualificationRunnerXpcError::OutcomeUnknown);
        }
        let _flight = SessionFlight(self);
        if self.terminal.load(Ordering::Acquire) {
            return Err(QualificationRunnerXpcError::Invalidated);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut session = self.lock();
            if self.terminal.load(Ordering::Acquire) {
                return Err(QualificationRunnerXpcError::Invalidated);
            }
            let session = session
                .as_mut()
                .ok_or(QualificationRunnerXpcError::Invalidated)?;
            let deadline = session.deadline();
            if Instant::now() >= deadline {
                return Err(QualificationRunnerXpcError::TimedOut);
            }
            let reply = session.session_mut().exchange(request)?;
            if self.terminal.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(QualificationRunnerXpcError::OutcomeUnknown);
            }
            Ok(reply)
        }));
        match result {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(error)) => {
                self.close();
                Err(error)
            }
            Err(_) => {
                self.close();
                Err(QualificationRunnerXpcError::Unavailable)
            }
        }
    }

    /// Marks the session terminal without waiting for an in-flight handler.
    ///
    /// Returns whether there was no handler retaining the admission slot.
    pub(crate) fn close(&self) -> bool {
        self.terminal.store(true, Ordering::Release);
        let idle = !self.in_flight.load(Ordering::Acquire);
        if idle {
            self.dispose_terminal();
        }
        idle
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn deadline(&self) -> Option<Instant> {
        if self.terminal.load(Ordering::Acquire) {
            return None;
        }
        self.lock()
            .as_ref()
            .map(crate::QualificationRunnerSessionLease::deadline)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    fn dispose_terminal(&self) {
        if !self.terminal.load(Ordering::Acquire) || self.in_flight.load(Ordering::Acquire) {
            return;
        }
        let mut session = match self.session.try_lock() {
            Ok(session) => session,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let removed = session.take();
            drop(removed);
        }));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<crate::QualificationRunnerSessionLease>> {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn start_session(
    factory: &dyn QualificationRunnerSessionFactory,
    endpoint: crate::QualificationRunnerEndpoint,
    peer: QualificationRunnerPeer,
) -> Result<SessionSlot, QualificationRunnerXpcError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let receipt = QualificationRunnerSessionReceipt::random()?;
        factory
            .create_session(crate::QualificationRunnerSessionContext::new(
                endpoint, peer, receipt,
            ))
            .map(SessionSlot::new)
    }))
    .unwrap_or(Err(QualificationRunnerXpcError::Unavailable))
}

#[cfg(test)]
#[path = "qualification_runner_listener/tests.rs"]
mod tests;
