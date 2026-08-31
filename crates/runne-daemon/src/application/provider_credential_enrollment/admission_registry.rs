use std::collections::HashMap;
use std::sync::Mutex;

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialBeginIntentBinding, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostError, ProviderCredentialIntentConsumptionProof,
    ProviderCredentialRequestAuthorityIssuer, ProviderCredentialVerifyIntentBinding,
    VerifiedProtectedCredentialEnrollmentAdmission, VerifiedProtectedCredentialEnrollmentRequest,
    VerifyProviderCredential, protected_credential_native_intent_digest,
};

const MAX_PENDING_ADMISSIONS: usize = 64;

/// Daemon-owned one-use bridge from protected control to a V2 HTTP request.
///
/// The registry retains only a native-intent digest and non-Serde values. A
/// matching HTTP handoff removes the entry before returning authority material.
#[allow(dead_code)]
pub(crate) struct PendingCredentialHttpAdmissions {
    issuer: ProviderCredentialRequestAuthorityIssuer,
    state: Mutex<PendingCredentialHttpAdmissionState>,
}

struct PendingCredentialHttpAdmissionState {
    entries: HashMap<[u8; 32], PendingCredentialHttpAdmission>,
    consumed: HashMap<[u8; 32], u64>,
}

struct PendingCredentialHttpAdmission {
    protected_session_id: [u8; 16],
    action_provider_revision: [u8; 32],
    command_identity: [u8; 32],
    expires_at_unix_millis: u64,
    authority: ProviderCredentialBaseRequestAuthority,
    proof: ProviderCredentialIntentConsumptionProof,
    context: ProviderCredentialCommandContext,
}

#[allow(dead_code)]
impl PendingCredentialHttpAdmissions {
    #[must_use]
    pub(super) fn new(issuer: ProviderCredentialRequestAuthorityIssuer) -> Self {
        Self {
            issuer,
            state: Mutex::new(PendingCredentialHttpAdmissionState {
                entries: HashMap::new(),
                consumed: HashMap::new(),
            }),
        }
    }

    /// Registers one fully verified protected-control admission.
    pub(super) fn register(
        &self,
        request: VerifiedProtectedCredentialEnrollmentRequest,
        admission: VerifiedProtectedCredentialEnrollmentAdmission,
        context: ProviderCredentialCommandContext,
        now_unix_millis: u64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if now_unix_millis == 0 || admission.expires_at_unix_millis() <= now_unix_millis {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let native_intent_digest = request.native_intent_digest();
        let protected_session_id = request.protected_session_id();
        let action_provider_revision = request.action_provider_revision_binding();
        let command_identity = request.command_identity_binding();
        let expires_at_unix_millis = admission.expires_at_unix_millis();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        state
            .entries
            .retain(|_, value| value.expires_at_unix_millis > now_unix_millis);
        state.consumed.retain(|_, expiry| *expiry > now_unix_millis);
        if state.entries.contains_key(&native_intent_digest)
            || state.consumed.contains_key(&native_intent_digest)
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        if state.entries.len() >= MAX_PENDING_ADMISSIONS {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        let (authority, proof) = self
            .issuer
            .issue_from_verified_enrollment(request, admission)?;
        state.entries.insert(
            native_intent_digest,
            PendingCredentialHttpAdmission {
                protected_session_id,
                action_provider_revision,
                command_identity,
                expires_at_unix_millis,
                authority,
                proof,
                context,
            },
        );
        Ok(())
    }

    /// Consumes the exact admission bound to a live session and V2 command.
    /// Resolves a parsed HTTP begin command against the consumed control claim.
    pub(super) fn resolve_begin(
        &self,
        command: &BeginProviderCredentialEnrollment,
        protected_session_id: [u8; 16],
        now_unix_millis: u64,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialIntentConsumptionProof,
            ProviderCredentialCommandContext,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let entry = self.take_entry(command.native_intent_id(), now_unix_millis)?;
        let binding = ProviderCredentialBeginIntentBinding::new(command, &entry.context);
        if entry.protected_session_id != protected_session_id
            || entry.action_provider_revision != *binding.action_provider_revision_digest()
            || entry.command_identity != *binding.command_identity_digest()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok((entry.authority, entry.proof, entry.context))
    }

    /// Resolves a parsed HTTP verify command against the consumed control claim.
    pub(super) fn resolve_verify(
        &self,
        command: &VerifyProviderCredential,
        protected_session_id: [u8; 16],
        now_unix_millis: u64,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialIntentConsumptionProof,
            ProviderCredentialCommandContext,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let entry = self.take_entry(command.native_intent_id(), now_unix_millis)?;
        let binding = ProviderCredentialVerifyIntentBinding::new(command, &entry.context);
        if entry.protected_session_id != protected_session_id
            || entry.action_provider_revision != *binding.action_provider_revision_digest()
            || entry.command_identity != *binding.command_identity_digest()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok((entry.authority, entry.proof, entry.context))
    }

    fn take_entry(
        &self,
        native_intent_id: &str,
        now_unix_millis: u64,
    ) -> Result<PendingCredentialHttpAdmission, ProviderCredentialEnrollmentHostError> {
        if now_unix_millis == 0 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let native_intent_digest = protected_credential_native_intent_digest(native_intent_id);
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        state
            .entries
            .retain(|_, value| value.expires_at_unix_millis > now_unix_millis);
        state.consumed.retain(|_, expiry| *expiry > now_unix_millis);
        let entry = state
            .entries
            .remove(&native_intent_digest)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        state
            .consumed
            .insert(native_intent_digest, entry.expires_at_unix_millis);
        Ok(entry)
    }
}

#[cfg(test)]
#[path = "admission_registry_tests.rs"]
mod tests;
