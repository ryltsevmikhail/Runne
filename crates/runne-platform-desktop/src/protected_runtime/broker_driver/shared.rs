use super::{
    BrokerControl, CredentialBrokerTransferAuthenticator, ProtectedBundledRuntimeError,
    ProviderCredentialBrokerHandoffContext, ProviderCredentialBrokerHandoffFrame, UnixStream,
    broker_offer,
};
use crate::protected_runtime::{
    BundledRuntimeLifecycleState, ProtectedBundledRuntimeSupervisor,
    control_response::RejoinRegistration, read_frame,
};
use runne_api::ProtectedCredentialRecoveryBootstrap;
use std::sync::{Arc, Mutex};

struct SharedControl<R> {
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    bootstrap: ProtectedCredentialRecoveryBootstrap,
    runtime: tokio::runtime::Handle,
    registration: R,
}

#[derive(Clone, Copy)]
struct ExpectedReply<'a> {
    context: &'a ProviderCredentialBrokerHandoffContext,
    phase: u8,
    purpose: u8,
    nonce: [u8; 16],
}

impl<R: RejoinRegistration> SharedControl<R> {
    fn receive(
        &self,
        auth: &CredentialBrokerTransferAuthenticator,
        expected: ExpectedReply<'_>,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        for attempt in 0..=1 {
            let prepared = {
                let mut guard = self
                    .supervisor
                    .lock()
                    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
                self.validate(&guard)?;
                let process = guard
                    .process
                    .as_mut()
                    .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
                let frame = read_frame(&mut process.channel)?;
                let now = clock()?;
                if ProviderCredentialBrokerHandoffFrame::decode_and_verify(
                    &frame,
                    auth,
                    expected.context,
                    expected.phase,
                    expected.purpose,
                    expected.nonce,
                    now,
                )
                .is_ok()
                {
                    return Ok(());
                }
                if attempt != 0 {
                    return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
                }
                guard.prepare_received_credential_service_rejoin(&frame)?
            };
            let registered = self
                .runtime
                .block_on(self.registration.register(prepared))?;
            let mut guard = self
                .supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            self.validate(&guard)?;
            guard.confirm_credential_service_rejoin(registered)?;
        }
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    }

    fn validate(
        &self,
        guard: &ProtectedBundledRuntimeSupervisor,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if guard.state != BundledRuntimeLifecycleState::Ready || guard.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = guard
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if process.graceful_requested || process.recovery_bootstrap()? != self.bootstrap {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        Ok(())
    }
}

fn clock() -> Result<u64, ProtectedBundledRuntimeError> {
    crate::MacOsContinuousClock::now_millis()
        .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)
}

impl<R: RejoinRegistration> BrokerControl for SharedControl<R> {
    fn offer(
        &mut self,
        context: &ProviderCredentialBrokerHandoffContext,
        authenticator: &CredentialBrokerTransferAuthenticator,
        purpose: u8,
    ) -> Result<[u8; 16], ProtectedBundledRuntimeError> {
        let nonce = {
            let mut guard = self
                .supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            self.validate(&guard)?;
            let process = guard
                .process
                .as_mut()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            let nonce =
                broker_offer::send(&mut process.channel, context, authenticator, purpose, clock)?;
            drop(guard);
            nonce
        };
        self.receive(
            authenticator,
            ExpectedReply {
                context,
                phase: ProviderCredentialBrokerHandoffFrame::PHASE_READY,
                purpose,
                nonce,
            },
        )?;
        Ok(nonce)
    }
    fn respond(
        &mut self,
        daemon_half: &UnixStream,
        binding: [u8; 32],
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let guard = self
            .supervisor
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        self.validate(&guard)?;
        guard
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?
            .respond_transport_offer(daemon_half, binding, authenticator)
    }
    fn acknowledge(
        &mut self,
        context: &ProviderCredentialBrokerHandoffContext,
        authenticator: &CredentialBrokerTransferAuthenticator,
        nonce: [u8; 16],
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.receive(
            authenticator,
            ExpectedReply {
                context,
                phase: ProviderCredentialBrokerHandoffFrame::PHASE_ACK,
                purpose: ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
                nonce,
            },
        )
    }
}

#[cfg(feature = "test-support")]
mod test_support;
#[cfg(all(test, feature = "test-support"))]
mod tests;
#[cfg(feature = "test-support")]
pub use test_support::test_only_crossed_broker_offer;

impl ProtectedBundledRuntimeSupervisor {
    /// Runs one native handoff on one blocking owner, servicing bounded framed rejoin.
    /// Caller must retain exclusive runtime/updater leases and a non-cancellable owner
    /// until this future returns, including transferring retained failure cleanup.
    ///
    /// # Errors
    /// Rejects changed launch, invalid registration or handoff; retains post-relinquishment reap.
    pub async fn run_credential_writer_handoff_with_rejoin(
        supervisor: Arc<Mutex<Self>>,
        confirmed: &crate::ConfirmedInstalledNativeEnrollment,
        mode: super::CredentialWriterHandoffMode,
    ) -> Result<super::CredentialWriterHandoff, super::CredentialWriterHandoffError> {
        let (bootstrap, facts, context, launch, authenticator) = {
            let guard = supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            if guard.state != BundledRuntimeLifecycleState::Ready || guard.pending_profile.is_some()
            {
                return Err(ProtectedBundledRuntimeError::InvalidState.into());
            }
            let process = guard
                .process
                .as_ref()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            if process.graceful_requested {
                return Err(ProtectedBundledRuntimeError::InvalidState.into());
            }
            let (owned, facts) = process.v3_enrollment_facts()?;
            let context = ProviderCredentialBrokerHandoffContext::new(
                *owned.stable().authority_id(),
                *owned.session_id(),
                owned.launch_generation(),
                facts.binding(),
            )
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            let captured = (
                process.recovery_bootstrap()?,
                facts,
                context,
                confirmed.verified_macos_writer_launch()?,
                CredentialBrokerTransferAuthenticator::from_protected_activation(&process.keys),
            );
            drop(guard);
            captured
        };
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut control = SharedControl {
                supervisor,
                bootstrap,
                runtime,
                registration: crate::protected_runtime::control_response::NativeRegistration,
            };
            let result = super::drive(&mut control, launch, mode, facts, &authenticator, &context);
            if result.is_err() {
                let mut guard = control
                    .supervisor
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(process) = guard.process.as_mut()
                    && process
                        .recovery_bootstrap()
                        .is_ok_and(|current| current == control.bootstrap)
                {
                    process.poison_root_transport();
                }
            }
            result
        })
        .await
        .map_err(|_| {
            super::CredentialWriterHandoffError::from(ProtectedBundledRuntimeError::InvalidState)
        })?
    }
}
