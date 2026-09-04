use super::reap_guard::{ExactWriterCleanup, RetainedWriterCleanup};
use super::reaper_registry::{CredentialWriterReaperRegistry, ReaperOperationId};
use super::*;
use runne_api::BeginProviderCredentialEnrollment;
use runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin;
use std::sync::Arc;
#[path = "runner_exchange.rs"]
mod exchange;

pub(in crate::provider_credential_enrollment) trait RecoverableWriterHandoff {
    type Error;

    fn reap_exact_writer(&mut self) -> Result<(), Self::Error>;

    fn maintain_exact_writer(&mut self) -> Result<(), Self::Error> {
        self.reap_exact_writer()
    }
}

impl RecoverableWriterHandoff for runne_platform_desktop::CredentialWriterHandoff {
    type Error = runne_platform_desktop::ProtectedBundledRuntimeError;

    fn reap_exact_writer(&mut self) -> Result<(), Self::Error> {
        self.reap_exact_writer()
    }

    fn maintain_exact_writer(&mut self) -> Result<(), Self::Error> {
        self.reap_exact_writer_bounded(std::time::Duration::from_millis(100))
    }
}

pub struct ProtectedWriterCleanup<H = runne_platform_desktop::CredentialWriterHandoff> {
    handoff: H,
    supervisor: Arc<std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>>,
    _recovery_resources: Option<Arc<super::recovery::RecoveryResources>>,
}

impl<H> ProtectedWriterCleanup<H> {
    #[cfg(test)]
    pub(in crate::provider_credential_enrollment) const fn new(
        handoff: H,
        supervisor: Arc<
            std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>,
        >,
    ) -> Self {
        Self {
            handoff,
            supervisor,
            _recovery_resources: None,
        }
    }

    pub(super) const fn with_recovery_resources(
        handoff: H,
        supervisor: Arc<
            std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>,
        >,
        resources: Arc<super::recovery::RecoveryResources>,
    ) -> Self {
        Self {
            handoff,
            supervisor,
            _recovery_resources: Some(resources),
        }
    }
}

impl<H> ExactWriterCleanup for ProtectedWriterCleanup<H>
where
    H: RecoverableWriterHandoff<Error = runne_platform_desktop::ProtectedBundledRuntimeError>,
{
    type Error = runne_platform_desktop::ProtectedBundledRuntimeError;

    fn finish_exact(&mut self) -> Result<(), Self::Error> {
        self.handoff.reap_exact_writer()
    }

    fn abort_exact(&mut self) -> Result<(), Self::Error> {
        let abort = self
            .supervisor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .abort_protected_credential_enrollment();
        let reap = self.handoff.reap_exact_writer();
        abort.and(reap)
    }

    fn retry_exact(&mut self) -> Result<(), Self::Error> {
        self.handoff.reap_exact_writer()
    }

    fn maintain_exact(&mut self) -> Result<(), Self::Error> {
        self.handoff.maintain_exact_writer()
    }
}

pub type ProtectedWriterReaperRegistry = CredentialWriterReaperRegistry<ProtectedWriterCleanup>;

pub(super) const fn pair_cleanup<H>(
    handoff: H,
    supervisor: Arc<std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>>,
    resources: Arc<super::recovery::RecoveryResources>,
) -> ProtectedWriterCleanup<H> {
    ProtectedWriterCleanup::with_recovery_resources(handoff, supervisor, resources)
}

pub(super) fn retain_failed_handoff(
    error: runne_platform_desktop::CredentialWriterHandoffError,
    operation: &ReaperOperationId,
    reapers: &ProtectedWriterReaperRegistry,
    cleanup: impl FnOnce(runne_platform_desktop::CredentialWriterHandoff) -> ProtectedWriterCleanup,
) {
    if let (_, Some(handoff)) = error.into_parts() {
        reapers.retain_after_initial_failure(operation.clone(), cleanup(handoff));
    }
}

fn pair_handoff(
    exchange: &PreparedCredentialEnrollmentExchange,
    supervisor: &Arc<std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>>,
    operation: &ReaperOperationId,
    reapers: &ProtectedWriterReaperRegistry,
) -> Result<runne_platform_desktop::CredentialWriterHandoff, PreparedCredentialEnrollmentError> {
    let result = tauri::async_runtime::block_on(
        runne_platform_desktop::ProtectedBundledRuntimeSupervisor::run_credential_writer_handoff_with_rejoin(
            Arc::clone(supervisor),
            &exchange.resources.installed,
            exchange.request.writer_handoff_mode(),
        ),
    );
    result.map_err(|error| {
        retain_failed_handoff(error, operation, reapers, |handoff| {
            pair_cleanup(
                handoff,
                Arc::clone(supervisor),
                Arc::clone(&exchange.resources),
            )
        });
        PreparedCredentialEnrollmentError
    })
}

pub(super) fn begin_then_handoff<B, H, E: Default>(
    begin_operation: impl FnOnce() -> Result<B, E>,
    prepared: impl FnOnce(&B) -> bool,
    handoff: impl FnOnce(&B) -> Result<H, E>,
) -> Result<(B, H), E> {
    let snapshot = begin_operation()?;
    if !prepared(&snapshot) {
        return Err(E::default());
    }
    let retained = handoff(&snapshot)?;
    Ok((snapshot, retained))
}

impl PreparedCredentialEnrollmentExchange {
    /// Synchronously retains the protected transcript, writer ownership, and
    /// secret until exact terminal readback and bounded reap.
    pub(in crate::provider_credential_enrollment) fn run(
        mut self,
        registry: &CredentialIntentRegistry,
        reapers: Arc<ProtectedWriterReaperRegistry>,
    ) -> Result<Arc<super::recovery::RecoveryResources>, PreparedCredentialEnrollmentError> {
        self.run_retained(registry, reapers)?;
        Ok(self.resources)
    }

    fn run_retained(
        &mut self,
        registry: &CredentialIntentRegistry,
        reapers: Arc<ProtectedWriterReaperRegistry>,
    ) -> Result<(), PreparedCredentialEnrollmentError> {
        let secretless = exchange::secretless(self.request.action, self.material.is_some())?;
        self.resources
            .updater
            .revalidate_confirmed(&self.resources.installed)
            .map_err(|()| PreparedCredentialEnrollmentError)?;
        let intent = self
            .intent
            .take()
            .ok_or(PreparedCredentialEnrollmentError)?;
        let consumed = registry
            .consume(
                intent,
                &self.window,
                self.request.renderer_generation,
                self.request,
                self.intent_session,
                Instant::now(),
            )
            .map_err(|_| PreparedCredentialEnrollmentError)?;
        let command_id = uuid::Uuid::now_v7().to_string();
        let reaper_operation =
            ReaperOperationId::new(&command_id).ok_or(PreparedCredentialEnrollmentError)?;
        let command = BeginProviderCredentialEnrollment::new(
            self.request.action,
            self.request.provider,
            self.request.expected_revision,
            &command_id,
            &command_id,
            consumed.daemon_id(),
        )
        .map_err(|_| PreparedCredentialEnrollmentError)?;
        let begin =
            NativeProtectedCredentialEnrollmentBegin::new(command, self.native_confirmation)
                .map_err(|_| PreparedCredentialEnrollmentError)?;
        let supervisor = self.resources.runtime.supervisor_handle();
        let (enrollment, retained_handoff) = begin_then_handoff(
            || {
                supervisor
                    .lock()
                    .map_err(|_| PreparedCredentialEnrollmentError)?
                    .begin_protected_credential_enrollment(begin)
                    .map_err(|_| PreparedCredentialEnrollmentError)
            },
            |enrollment| enrollment.snapshot().broker_rendezvous_id().is_some(),
            |_| pair_handoff(self, &supervisor, &reaper_operation, &reapers),
        )?;
        let mut handoff = RetainedWriterCleanup::new(
            pair_cleanup(
                retained_handoff,
                Arc::clone(&supervisor),
                Arc::clone(&self.resources),
            ),
            reaper_operation,
            reapers,
        );
        let exchange = (|| {
            if secretless {
                return exchange::finish_control_only(Arc::clone(&supervisor), enrollment);
            }
            let mut enrollment = tauri::async_runtime::block_on(
                runne_platform_desktop::ProtectedBundledRuntimeSupervisor::receive_credential_secret_relay_with_rejoin(
                    Arc::clone(&supervisor), enrollment,
                ),
            ).map_err(|_| PreparedCredentialEnrollmentError)?;
            let relay = enrollment
                .take_relay()
                .ok_or(PreparedCredentialEnrollmentError)?;
            let secret = self
                .material
                .take()
                .ok_or(PreparedCredentialEnrollmentError)?
                .into_pipe_bytes()
                .into_zeroizing();
            handoff
                .cleanup_mut()
                .ok_or(PreparedCredentialEnrollmentError)?
                .handoff
                .take_pair_secret_relay()
                .ok_or(PreparedCredentialEnrollmentError)?
                .seal_and_write(&relay, secret)
                .map_err(|_| PreparedCredentialEnrollmentError)?;
            let enrollment = tauri::async_runtime::block_on(
                runne_platform_desktop::ProtectedBundledRuntimeSupervisor::finish_protected_credential_enrollment_with_rejoin(
                    Arc::clone(&supervisor), enrollment, &relay,
                ),
            ).map_err(|_| PreparedCredentialEnrollmentError)?;
            (enrollment.terminal() && terminal_is_success(enrollment.snapshot().state()))
                .then_some(())
                .ok_or(PreparedCredentialEnrollmentError)
        })();
        let reaped = if exchange.is_err() {
            handoff.abort()
        } else {
            handoff.finish()
        }
        .map_err(|_| PreparedCredentialEnrollmentError);
        exchange.and(reaped)
    }
}

pub(super) const fn terminal_is_success(
    state: runne_api::ProviderCredentialOperationStateV2,
) -> bool {
    matches!(
        state,
        runne_api::ProviderCredentialOperationStateV2::Completed
    )
}

#[cfg(test)]
#[path = "runner_round4_tests.rs"]
mod round4_tests;
