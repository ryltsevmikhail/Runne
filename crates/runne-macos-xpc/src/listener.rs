use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};

use zeroize::Zeroizing;

use crate::{
    CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole,
    CredentialServiceXpcError,
};

#[cfg(target_os = "macos")]
mod native;

/// Domain handler invoked after native endpoint and peer admission.
pub trait CredentialServiceRequestHandler: Send + Sync {
    /// Consumes one bounded frame and returns one bounded reply frame.
    ///
    /// # Errors
    ///
    /// Returns only a closed transport/service disposition.
    fn handle(
        &self,
        role: CredentialServiceEndpointRole,
        request: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError>;
}

pub fn invoke_handler(
    handler: &dyn CredentialServiceRequestHandler,
    role: CredentialServiceEndpointRole,
    request: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handler.handle(role, request)
    }))
    .unwrap_or(Err(CredentialServiceXpcError::Unavailable))
}

struct ConnectionActivityState {
    admission: Mutex<AdmissionState>,
}

struct AdmissionState {
    active: usize,
    accepting: bool,
}

#[derive(Clone)]
struct ConnectionActivity(Arc<ConnectionActivityState>);

impl ConnectionActivity {
    fn new() -> Self {
        Self(Arc::new(ConnectionActivityState {
            admission: Mutex::new(AdmissionState {
                active: 0,
                accepting: true,
            }),
        }))
    }

    fn try_open(&self) -> Option<ConnectionGuard> {
        let mut admission = self.lock();
        if !admission.accepting {
            return None;
        }
        admission.active += 1;
        drop(admission);
        Some(ConnectionGuard {
            activity: self.clone(),
            closed: AtomicBool::new(false),
        })
    }

    fn active(&self) -> usize {
        self.lock().active
    }

    fn close_admission(&self) {
        self.lock().accepting = false;
    }

    fn reopen_admission(&self) {
        self.lock().accepting = true;
    }

    fn lock(&self) -> MutexGuard<'_, AdmissionState> {
        self.0
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct ConnectionGuard {
    activity: ConnectionActivity,
    closed: AtomicBool,
}

impl ConnectionGuard {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let mut admission = self.activity.lock();
            admission.active = admission.active.saturating_sub(1);
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.close();
    }
}

/// Retained native listener; no Foundation object crosses this boundary.
pub struct CredentialServiceXpcListener {
    #[cfg(target_os = "macos")]
    native: native::NativeListener,
}

impl CredentialServiceXpcListener {
    /// Binds one exact role endpoint with its client signing requirement.
    ///
    /// # Errors
    ///
    /// Returns typed unsupported off macOS or a closed native failure.
    pub fn bind(
        configuration: &CredentialServiceEndpointConfiguration,
        handler: Arc<dyn CredentialServiceRequestHandler>,
    ) -> Result<Self, CredentialServiceXpcError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                native: native::NativeListener::bind(configuration, handler)?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (configuration, handler);
            Err(CredentialServiceXpcError::Unsupported)
        }
    }

    /// Invalidates the native listener immediately.
    pub fn invalidate(&self) {
        #[cfg(target_os = "macos")]
        self.native.invalidate();
    }

    /// Returns the exact number of accepted connections not yet invalidated.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        #[cfg(target_os = "macos")]
        return self.native.active_connections();
        #[cfg(not(target_os = "macos"))]
        return 0;
    }

    /// Closes admission before an idle snapshot is finalized.
    pub fn close_admission(&self) {
        #[cfg(target_os = "macos")]
        self.native.close_admission();
    }

    /// Reopens admission when the final idle snapshot finds live work.
    pub fn reopen_admission(&self) {
        #[cfg(target_os = "macos")]
        self.native.reopen_admission();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::ConnectionActivity;

    #[test]
    fn connection_activity_is_exact_and_idempotent() {
        let activity = ConnectionActivity::new();
        assert_eq!(activity.active(), 0);
        let first = activity.try_open().expect("admission open");
        let second = activity.try_open().expect("admission open");
        assert_eq!(activity.active(), 2);
        first.close();
        first.close();
        assert_eq!(activity.active(), 1);
        drop(second);
        assert_eq!(activity.active(), 0);
    }

    #[test]
    fn closed_admission_cannot_race_a_new_accepted_connection() {
        for _ in 0..128 {
            let activity = ConnectionActivity::new();
            let barrier = Arc::new(Barrier::new(2));
            let opener_activity = activity.clone();
            let opener_barrier = barrier.clone();
            let opener = thread::spawn(move || {
                opener_barrier.wait();
                opener_activity.try_open()
            });
            barrier.wait();
            activity.close_admission();
            let guard = opener.join().expect("opener");
            assert_eq!(activity.active(), usize::from(guard.is_some()));
            drop(guard);
            assert_eq!(activity.active(), 0);
        }

        activity_for_reopen_is_admitted();
    }

    fn activity_for_reopen_is_admitted() {
        let activity = ConnectionActivity::new();
        activity.close_admission();
        activity.reopen_admission();
        assert!(activity.try_open().is_some());
    }
}
