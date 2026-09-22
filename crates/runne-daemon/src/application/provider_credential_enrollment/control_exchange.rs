use super::admission_registry::PendingCredentialAdmissions;
use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostError, VerifiedProtectedCredentialEnrollmentAdmission,
    VerifiedProtectedCredentialEnrollmentRequest, VerifyProviderCredential,
};

/// Daemon-retained, non-authority bindings from authenticated control state.
pub(super) struct DaemonCredentialHttpAdmissionExpectation {
    protected_session_id: [u8; 16],
    protected_session_binding: [u8; 32],
    action_provider_revision: [u8; 32],
    command_identity: [u8; 32],
    native_intent_digest: [u8; 32],
    request_sequence: u64,
    admission_sequence: u64,
    authenticated_tauri_peer: [u8; 32],
    expires_at_unix_millis: u64,
}

impl DaemonCredentialHttpAdmissionExpectation {
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(super) fn new(
        protected_session_id: [u8; 16],
        protected_session_binding: [u8; 32],
        action_provider_revision: [u8; 32],
        command_identity: [u8; 32],
        native_intent_digest: [u8; 32],
        request_sequence: u64,
        admission_sequence: u64,
        authenticated_tauri_peer: [u8; 32],
        expires_at_unix_millis: u64,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if protected_session_id == [0; 16]
            || [
                protected_session_binding,
                action_provider_revision,
                command_identity,
                native_intent_digest,
                authenticated_tauri_peer,
            ]
            .contains(&[0; 32])
            || request_sequence == 0
            || request_sequence.checked_add(1) != Some(admission_sequence)
            || expires_at_unix_millis == 0
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(Self {
            protected_session_id,
            protected_session_binding,
            action_provider_revision,
            command_identity,
            native_intent_digest,
            request_sequence,
            admission_sequence,
            authenticated_tauri_peer,
            expires_at_unix_millis,
        })
    }

    fn matches(
        &self,
        request: &VerifiedProtectedCredentialEnrollmentRequest,
        admission: &VerifiedProtectedCredentialEnrollmentAdmission,
        now_unix_millis: u64,
    ) -> bool {
        now_unix_millis != 0
            && self.expires_at_unix_millis > now_unix_millis
            && request.protected_session_id() == self.protected_session_id
            && admission.protected_session_binding() == self.protected_session_binding
            && request.action_provider_revision_binding() == self.action_provider_revision
            && request.command_identity_binding() == self.command_identity
            && request.native_intent_digest() == self.native_intent_digest
            && request.sequence() == self.request_sequence
            && admission.sequence() == self.admission_sequence
            && admission.expires_at_unix_millis() == self.expires_at_unix_millis
            && admission.authenticated_tauri_peer_binding() == self.authenticated_tauri_peer
    }
}

/// Only verified protected frames can enter this daemon-local HTTP bridge.
#[allow(dead_code)]
pub(super) struct DaemonAuthenticatedCredentialHttpAdmissionExchange {
    registry: PendingCredentialAdmissions,
    expected: DaemonCredentialHttpAdmissionExpectation,
}

#[allow(dead_code)]
pub(super) struct RegisteredCredentialHttpAdmissionExchange {
    registry: PendingCredentialAdmissions,
}

#[allow(dead_code)]
impl DaemonAuthenticatedCredentialHttpAdmissionExchange {
    pub(super) const fn new(
        registry: PendingCredentialAdmissions,
        expected: DaemonCredentialHttpAdmissionExpectation,
    ) -> Self {
        Self { registry, expected }
    }

    pub(super) fn register(
        self,
        request: VerifiedProtectedCredentialEnrollmentRequest,
        admission: VerifiedProtectedCredentialEnrollmentAdmission,
        context: ProviderCredentialCommandContext,
        now_unix_millis: u64,
        command_provider: runne_api::ProviderCredentialProviderV2,
    ) -> Result<RegisteredCredentialHttpAdmissionExchange, ProviderCredentialEnrollmentHostError>
    {
        if !self.expected.matches(&request, &admission, now_unix_millis) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.registry.register(
            request,
            admission,
            context,
            now_unix_millis,
            command_provider,
        )?;
        Ok(RegisteredCredentialHttpAdmissionExchange {
            registry: self.registry,
        })
    }
}

#[allow(dead_code)]
impl RegisteredCredentialHttpAdmissionExchange {
    pub(super) fn resolve_begin(
        &self,
        protected_session_id: [u8; 16],
        command: &BeginProviderCredentialEnrollment,
        now_unix_millis: u64,
    ) -> Result<
        (
            runne_api::ProviderCredentialBaseRequestAuthority,
            runne_api::ProviderCredentialIntentConsumptionProof,
            ProviderCredentialCommandContext,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        self.registry
            .resolve_begin(command, protected_session_id, now_unix_millis)
    }

    pub(super) fn resolve_verify(
        &self,
        protected_session_id: [u8; 16],
        command: &VerifyProviderCredential,
        now_unix_millis: u64,
    ) -> Result<
        (
            runne_api::ProviderCredentialBaseRequestAuthority,
            runne_api::ProviderCredentialIntentConsumptionProof,
            ProviderCredentialCommandContext,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        self.registry
            .resolve_verify(command, protected_session_id, now_unix_millis)
    }
}
