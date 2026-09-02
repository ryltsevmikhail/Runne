//! Role-specific, fail-closed credential-service transport ports.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use zeroize::Zeroizing;

mod desktop;
mod runtime;
mod writer;

pub use desktop::CredentialServiceDesktopPort;
pub use runtime::CredentialServiceRuntimePort;
pub use writer::CredentialServiceWriterPort;

/// Absolute native transport ceiling, aligned with the public service codec.
pub const MAX_CREDENTIAL_SERVICE_FRAME_BYTES: usize = 16 * 1024;

macro_rules! credential_service_frame {
    ($name:ident) => {
        /// Move-only, zeroizing bytes for exactly one service endpoint direction.
        ///
        /// ```compile_fail
        #[doc = concat!("fn needs_clone<T: Clone>() {}\nneeds_clone::<runne_platform_ports::credential_service::", stringify!($name), ">();")]
        /// ```
        /// ```compile_fail
        #[doc = concat!("fn needs_debug<T: core::fmt::Debug>() {}\nneeds_debug::<runne_platform_ports::credential_service::", stringify!($name), ">();")]
        /// ```
        pub struct $name(Zeroizing<Vec<u8>>);

        impl $name {
            /// Accepts an already-zeroizing, non-empty bounded wire frame.
            ///
            /// # Errors
            ///
            /// Returns a closed rejection for an empty or oversized frame.
            pub fn from_zeroizing(
                bytes: Zeroizing<Vec<u8>>,
            ) -> Result<Self, CredentialServicePortError> {
                if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_SERVICE_FRAME_BYTES {
                    return Err(CredentialServicePortError::Rejected);
                }
                Ok(Self(bytes))
            }

            /// Borrows bytes only for the duration of one native transport call.
            pub fn with_bytes<T>(&self, use_bytes: impl FnOnce(&[u8]) -> T) -> T {
                use_bytes(&self.0)
            }

            /// Transfers ownership into a native adapter without making a copy.
            #[must_use]
            pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
                self.0
            }
        }
    };
}

credential_service_frame!(CredentialServiceDesktopRequest);
credential_service_frame!(CredentialServiceDesktopReply);
credential_service_frame!(CredentialServiceRuntimeRequest);
credential_service_frame!(CredentialServiceRuntimeReply);
credential_service_frame!(CredentialServiceWriterRequest);
credential_service_frame!(CredentialServiceWriterReply);

/// Sendable future returned by each native credential-service call.
pub type CredentialServicePortFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, CredentialServicePortError>> + Send + 'a>>;

/// Shared cancellation signal without native handles or error payloads.
#[derive(Clone)]
pub struct CredentialServiceCancellation {
    state: Arc<CredentialServiceCancellationState>,
}

#[derive(Default)]
struct CredentialServiceCancellationState {
    cancelled: AtomicBool,
    next_waiter_id: AtomicUsize,
    waiters: Mutex<Vec<(usize, Waker)>>,
}

impl Default for CredentialServiceCancellation {
    fn default() -> Self {
        Self {
            state: Arc::new(CredentialServiceCancellationState::default()),
        }
    }
}

impl CredentialServiceCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        if self.state.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        for (_, waiter) in self.waiters().drain(..) {
            waiter.wake();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    /// Resolves promptly when any clone cancels this signal.
    #[must_use]
    pub fn cancelled(&self) -> CredentialServiceCancellationFuture {
        CredentialServiceCancellationFuture {
            cancellation: self.clone(),
            waiter_id: None,
        }
    }

    fn waiters(&self) -> MutexGuard<'_, Vec<(usize, Waker)>> {
        self.state
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Awaitable view of a live credential-service cancellation signal.
pub struct CredentialServiceCancellationFuture {
    cancellation: CredentialServiceCancellation,
    waiter_id: Option<usize>,
}

impl Future for CredentialServiceCancellationFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cancellation.is_cancelled() {
            return Poll::Ready(());
        }
        let waiter_id = if let Some(waiter_id) = self.waiter_id {
            waiter_id
        } else {
            let waiter_id = self
                .cancellation
                .state
                .next_waiter_id
                .fetch_add(1, Ordering::Relaxed);
            self.waiter_id = Some(waiter_id);
            waiter_id
        };
        let mut waiters = self.cancellation.waiters();
        if self.cancellation.is_cancelled() {
            return Poll::Ready(());
        }
        if let Some((_, waiter)) = waiters.iter_mut().find(|(id, _)| *id == waiter_id) {
            if !waiter.will_wake(context.waker()) {
                waiter.clone_from(context.waker());
            }
        } else {
            waiters.push((waiter_id, context.waker().clone()));
        }
        Poll::Pending
    }
}

impl Drop for CredentialServiceCancellationFuture {
    fn drop(&mut self) {
        if let Some(waiter_id) = self.waiter_id {
            self.cancellation
                .waiters()
                .retain(|(id, _)| *id != waiter_id);
        }
    }
}

#[cfg(test)]
impl CredentialServiceCancellation {
    fn test_waiter_count(&self) -> usize {
        self.waiters().len()
    }
}

impl fmt::Debug for CredentialServiceCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(if self.is_cancelled() {
            "CredentialServiceCancellation(cancelled)"
        } else {
            "CredentialServiceCancellation(active)"
        })
    }
}

/// Exact deadline and live cancellation signal for one transport call.
pub struct CredentialServiceCallContext {
    deadline: Instant,
    cancellation: CredentialServiceCancellation,
}

impl CredentialServiceCallContext {
    #[must_use]
    pub const fn new(deadline: Instant, cancellation: CredentialServiceCancellation) -> Self {
        Self {
            deadline,
            cancellation,
        }
    }

    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    #[must_use]
    pub const fn cancellation(&self) -> &CredentialServiceCancellation {
        &self.cancellation
    }
}

/// Closed transport failures; native error details remain adapter-local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServicePortError {
    /// The request was rejected before native dispatch.
    Rejected,
    /// This platform has no native implementation.
    Unsupported,
    /// The endpoint was unavailable before dispatch.
    Unavailable,
    /// The deadline was reached before dispatch.
    TimedOut,
    /// Cancellation was observed before dispatch.
    Cancelled,
    /// Interruption was observed before dispatch.
    Interrupted,
    /// Invalidation was observed before dispatch.
    Invalidated,
    /// A reply was received but violated the bounded protocol.
    InvalidReply,
    /// Native dispatch occurred, so the effect requires reconciliation.
    OutcomeUnknown,
}

impl fmt::Display for CredentialServicePortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential service call failed")
    }
}

impl std::error::Error for CredentialServicePortError {}

#[cfg(test)]
mod tests;
