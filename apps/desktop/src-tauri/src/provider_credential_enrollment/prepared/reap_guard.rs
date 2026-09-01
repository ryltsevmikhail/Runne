use std::sync::{Arc, Mutex, MutexGuard};

pub(in crate::provider_credential_enrollment) trait ExactWriterCleanup {
    type Error;

    fn finish_exact(&mut self) -> Result<(), Self::Error>;
    fn abort_exact(&mut self) -> Result<(), Self::Error>;
    fn retry_exact(&mut self) -> Result<(), Self::Error> {
        self.finish_exact()
    }
}

pub(in crate::provider_credential_enrollment) struct ExactWriterRecovery<C> {
    retained: Arc<Mutex<Vec<C>>>,
}

impl<C> ExactWriterRecovery<C> {
    pub(in crate::provider_credential_enrollment) fn new() -> Self {
        Self {
            retained: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn retain(&self, cleanup: C) {
        recover_lock(&self.retained).push(cleanup);
    }

    #[cfg(test)]
    pub(in crate::provider_credential_enrollment) fn is_empty(&self) -> bool {
        recover_lock(&self.retained).is_empty()
    }
}

impl<C: ExactWriterCleanup> ExactWriterRecovery<C> {
    pub(in crate::provider_credential_enrollment) fn retry_exact(&self) -> bool {
        let retained = std::mem::take(&mut *recover_lock(&self.retained));
        let mut failed = Vec::new();
        for mut cleanup in retained {
            if cleanup.retry_exact().is_err() {
                failed.push(cleanup);
            }
        }
        let mut slot = recover_lock(&self.retained);
        slot.extend(failed);
        slot.is_empty()
    }
}

impl<C> Clone for ExactWriterRecovery<C> {
    fn clone(&self) -> Self {
        Self {
            retained: Arc::clone(&self.retained),
        }
    }
}

pub(in crate::provider_credential_enrollment) struct RetainedWriterCleanup<C: ExactWriterCleanup> {
    cleanup: Option<C>,
    recovery: ExactWriterRecovery<C>,
}

impl<C: ExactWriterCleanup> RetainedWriterCleanup<C> {
    pub(in crate::provider_credential_enrollment) const fn new(
        cleanup: C,
        recovery: ExactWriterRecovery<C>,
    ) -> Self {
        Self {
            cleanup: Some(cleanup),
            recovery,
        }
    }

    pub(super) const fn cleanup_mut(&mut self) -> Option<&mut C> {
        self.cleanup.as_mut()
    }

    pub(super) fn finish(mut self) -> Result<(), C::Error> {
        let Some(mut cleanup) = self.cleanup.take() else {
            return Ok(());
        };
        let result = cleanup.finish_exact();
        if result.is_err() {
            self.recovery.retain(cleanup);
        }
        result
    }

    pub(super) fn abort(mut self) -> Result<(), C::Error> {
        let Some(mut cleanup) = self.cleanup.take() else {
            return Ok(());
        };
        let result = cleanup.abort_exact();
        if result.is_err() {
            self.recovery.retain(cleanup);
        }
        result
    }
}

impl<C: ExactWriterCleanup> Drop for RetainedWriterCleanup<C> {
    fn drop(&mut self) {
        let Some(mut cleanup) = self.cleanup.take() else {
            return;
        };
        if cleanup.abort_exact().is_err() {
            self.recovery.retain(cleanup);
        }
    }
}

fn recover_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
