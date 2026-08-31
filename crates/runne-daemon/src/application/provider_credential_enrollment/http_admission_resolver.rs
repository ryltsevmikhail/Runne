#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the qualified protected HTTP composition remains deliberately unmounted"
    )
)]

use std::sync::Arc;

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentHostError,
    VerifyProviderCredential,
};
use runne_http::{
    ProviderCredentialEnrollmentHttpAdmission, ProviderCredentialEnrollmentHttpAdmissionResolver,
};

use super::control_exchange::RegisteredCredentialHttpAdmissionExchange;

/// Daemon-owned bridge from one registered control exchange to HTTP handlers.
pub(super) struct DaemonCredentialHttpAdmissionResolver {
    exchange: RegisteredCredentialHttpAdmissionExchange,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl DaemonCredentialHttpAdmissionResolver {
    pub(super) fn new(
        exchange: RegisteredCredentialHttpAdmissionExchange,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self { exchange, clock }
    }
}

impl ProviderCredentialEnrollmentHttpAdmissionResolver for DaemonCredentialHttpAdmissionResolver {
    fn resolve_begin(
        &self,
        protected_session_id: [u8; 16],
        command: &BeginProviderCredentialEnrollment,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        let (authority, proof, context) =
            self.exchange
                .resolve_begin(protected_session_id, command, (self.clock)())?;
        Ok(ProviderCredentialEnrollmentHttpAdmission::mutation(
            authority, proof, context,
        ))
    }

    fn resolve_verify(
        &self,
        protected_session_id: [u8; 16],
        command: &VerifyProviderCredential,
    ) -> Result<Arc<ProviderCredentialEnrollmentHttpAdmission>, ProviderCredentialEnrollmentHostError>
    {
        let (authority, proof, context) =
            self.exchange
                .resolve_verify(protected_session_id, command, (self.clock)())?;
        Ok(ProviderCredentialEnrollmentHttpAdmission::mutation(
            authority, proof, context,
        ))
    }
}
