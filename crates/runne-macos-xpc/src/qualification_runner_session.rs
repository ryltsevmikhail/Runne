use std::time::Instant;

use crate::qualification_runner::{
    QualificationRunnerEndpoint, QualificationRunnerPeer, QualificationRunnerSession,
    QualificationRunnerSessionReceipt, QualificationRunnerXpcError,
};

/// Opaque fixed-endpoint context for one newly accepted bootstrap connection.
pub struct QualificationRunnerSessionContext {
    endpoint: QualificationRunnerEndpoint,
    peer: QualificationRunnerPeer,
    receipt: QualificationRunnerSessionReceipt,
}

impl QualificationRunnerSessionContext {
    pub(crate) const fn new(
        endpoint: QualificationRunnerEndpoint,
        peer: QualificationRunnerPeer,
        receipt: QualificationRunnerSessionReceipt,
    ) -> Self {
        Self {
            endpoint,
            peer,
            receipt,
        }
    }

    #[must_use]
    pub const fn endpoint(&self) -> QualificationRunnerEndpoint {
        self.endpoint
    }

    #[must_use]
    pub const fn peer(&self) -> QualificationRunnerPeer {
        self.peer
    }

    /// Transfers the opaque receipt for later challenge and consume binding.
    #[must_use]
    pub const fn into_receipt(self) -> QualificationRunnerSessionReceipt {
        self.receipt
    }
}

/// A runner-owned session plus its monotonic transport expiry.
pub struct QualificationRunnerSessionLease {
    session: Box<dyn QualificationRunnerSession>,
    deadline: Instant,
}

impl QualificationRunnerSessionLease {
    /// Creates a session whose deadline remains in the future.
    ///
    /// # Errors
    ///
    /// Rejects a deadline that is already expired.
    pub fn new(
        session: Box<dyn QualificationRunnerSession>,
        deadline: Instant,
    ) -> Result<Self, QualificationRunnerXpcError> {
        if Instant::now() >= deadline {
            return Err(QualificationRunnerXpcError::TimedOut);
        }
        Ok(Self { session, deadline })
    }

    pub(crate) const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn session_mut(&mut self) -> &mut dyn QualificationRunnerSession {
        self.session.as_mut()
    }
}
