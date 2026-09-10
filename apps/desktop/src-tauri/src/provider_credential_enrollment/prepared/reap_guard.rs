use std::sync::Arc;

use super::reaper_registry::{CredentialWriterReaperRegistry, ReaperOperationId};

pub trait ExactWriterCleanup {
    type Error;

    fn finish_exact(&mut self) -> Result<(), Self::Error>;
    #[cfg_attr(
        all(not(test), not(all(target_os = "macos", target_arch = "aarch64"))),
        expect(
            dead_code,
            reason = "only native enrollment producers abort retained writers"
        )
    )]
    fn abort_exact(&mut self) -> Result<(), Self::Error>;

    fn retry_exact(&mut self) -> Result<(), Self::Error> {
        self.finish_exact()
    }

    fn maintain_exact(&mut self) -> Result<(), Self::Error> {
        self.retry_exact()
    }
}

#[cfg_attr(
    all(not(test), not(all(target_os = "macos", target_arch = "aarch64"))),
    expect(
        dead_code,
        reason = "only native enrollment producers retain writer cleanup"
    )
)]
pub(in crate::provider_credential_enrollment) struct RetainedWriterCleanup<
    C: ExactWriterCleanup + Send + 'static,
> {
    cleanup: Option<C>,
    operation: Option<ReaperOperationId>,
    registry: Arc<CredentialWriterReaperRegistry<C>>,
}

impl<C: ExactWriterCleanup + Send + 'static> RetainedWriterCleanup<C> {
    #[cfg_attr(
        all(not(test), not(all(target_os = "macos", target_arch = "aarch64"))),
        expect(
            dead_code,
            reason = "only native enrollment producers retain writer cleanup"
        )
    )]
    pub(in crate::provider_credential_enrollment) const fn new(
        cleanup: C,
        operation: ReaperOperationId,
        registry: Arc<CredentialWriterReaperRegistry<C>>,
    ) -> Self {
        Self {
            cleanup: Some(cleanup),
            operation: Some(operation),
            registry,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) const fn cleanup_mut(&mut self) -> Option<&mut C> {
        self.cleanup.as_mut()
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) fn finish(mut self) -> Result<(), C::Error> {
        self.run(ExactWriterCleanup::finish_exact)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) fn abort(mut self) -> Result<(), C::Error> {
        self.run(ExactWriterCleanup::abort_exact)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn run(&mut self, action: impl FnOnce(&mut C) -> Result<(), C::Error>) -> Result<(), C::Error> {
        let mut cleanup = self.cleanup.take().expect("retained writer cleanup");
        let result = action(&mut cleanup);
        if result.is_err() {
            self.registry.retain_after_initial_failure(
                self.operation.take().expect("reaper operation"),
                cleanup,
            );
        }
        result
    }
}

impl<C: ExactWriterCleanup + Send + 'static> Drop for RetainedWriterCleanup<C> {
    fn drop(&mut self) {
        let Some(mut cleanup) = self.cleanup.take() else {
            return;
        };
        if cleanup.abort_exact().is_err() {
            self.registry.retain_after_initial_failure(
                self.operation.take().expect("reaper operation"),
                cleanup,
            );
        }
    }
}
