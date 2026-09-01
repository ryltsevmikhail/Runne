pub(in crate::provider_credential_enrollment) trait ExactWriterCleanup {
    type Error;

    fn finish_exact(self) -> Result<(), Self::Error>;
    fn abort_exact(self) -> Result<(), Self::Error>;
}

pub(in crate::provider_credential_enrollment) struct RetainedWriterCleanup<C: ExactWriterCleanup> {
    cleanup: Option<C>,
    armed: bool,
}

impl<C: ExactWriterCleanup> RetainedWriterCleanup<C> {
    pub(in crate::provider_credential_enrollment) const fn new(cleanup: C) -> Self {
        Self {
            cleanup: Some(cleanup),
            armed: true,
        }
    }

    pub(super) const fn cleanup_mut(&mut self) -> Option<&mut C> {
        self.cleanup.as_mut()
    }

    pub(super) fn finish(mut self) -> Result<(), C::Error> {
        self.armed = false;
        self.cleanup
            .take()
            .expect("retained writer cleanup")
            .finish_exact()
    }

    pub(super) fn abort(mut self) -> Result<(), C::Error> {
        self.armed = false;
        self.cleanup
            .take()
            .expect("retained writer cleanup")
            .abort_exact()
    }
}

impl<C: ExactWriterCleanup> Drop for RetainedWriterCleanup<C> {
    fn drop(&mut self) {
        if self.armed
            && let Some(cleanup) = self.cleanup.take()
        {
            let _ = cleanup.abort_exact();
        }
    }
}
