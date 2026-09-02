use std::collections::HashMap;
use std::sync::Mutex;

use runne_api::{
    BeginProviderCredentialEnrollment, ProtectedActivationKeys,
    ProviderCredentialBaseRequestAuthority, ProviderCredentialBeginIntentBinding,
    ProviderCredentialBrokerTransferAuthority, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostError, ProviderCredentialIntentConsumptionProof,
    ProviderCredentialRequestAuthorityIssuer, ProviderCredentialVerifyIntentBinding,
    VerifiedProtectedCredentialEnrollmentAdmission, VerifiedProtectedCredentialEnrollmentRequest,
    VerifyProviderCredential, protected_credential_native_intent_digest,
};

const MAX_PENDING_ADMISSIONS: usize = 64;

/// Daemon-owned one-use bridge from protected control to an exact command.
///
/// The registry retains only a native-intent digest and non-Serde values. A
/// matching HTTP handoff removes the entry before returning authority material.
#[allow(dead_code)]
pub(crate) struct PendingCredentialAdmissions {
    issuer: ProviderCredentialRequestAuthorityIssuer,
    broker_keys: Option<ProtectedActivationKeys>,
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
    broker_transfer: Option<ProviderCredentialBrokerTransferAuthority>,
    context: ProviderCredentialCommandContext,
}

#[allow(dead_code)]
impl PendingCredentialAdmissions {
    #[must_use]
    pub(super) fn new(issuer: ProviderCredentialRequestAuthorityIssuer) -> Self {
        Self {
            issuer,
            broker_keys: None,
            state: Mutex::new(PendingCredentialHttpAdmissionState {
                entries: HashMap::new(),
                consumed: HashMap::new(),
            }),
        }
    }

    #[must_use]
    pub(super) fn new_with_broker_transfer(
        issuer: ProviderCredentialRequestAuthorityIssuer,
        keys: &ProtectedActivationKeys,
    ) -> Self {
        let mut admissions = Self::new(issuer);
        admissions.broker_keys = Some(keys.clone());
        admissions
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
        let (authority, proof, broker_transfer) = if let Some(keys) = &self.broker_keys {
            let admission = keys
                .bind_credential_broker_transfer(admission)
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
            let (authority, proof, transfer) = self
                .issuer
                .issue_from_verified_enrollment_with_broker_transfer(request, admission)?;
            (authority, proof, Some(transfer))
        } else {
            let (authority, proof) = self
                .issuer
                .issue_from_verified_enrollment(request, admission)?;
            (authority, proof, None)
        };
        state.entries.insert(
            native_intent_digest,
            PendingCredentialHttpAdmission {
                protected_session_id,
                action_provider_revision,
                command_identity,
                expires_at_unix_millis,
                authority,
                proof,
                broker_transfer,
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
        let entry = self.take_begin_entry(command, protected_session_id, now_unix_millis)?;
        Ok((entry.authority, entry.proof, entry.context))
    }

    pub(super) fn resolve_begin_with_broker_transfer(
        &self,
        command: &BeginProviderCredentialEnrollment,
        protected_session_id: [u8; 16],
        now_unix_millis: u64,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialIntentConsumptionProof,
            ProviderCredentialCommandContext,
            ProviderCredentialBrokerTransferAuthority,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let entry = self.take_begin_entry(command, protected_session_id, now_unix_millis)?;
        Ok((
            entry.authority,
            entry.proof,
            entry.context,
            entry
                .broker_transfer
                .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?,
        ))
    }

    fn take_begin_entry(
        &self,
        command: &BeginProviderCredentialEnrollment,
        protected_session_id: [u8; 16],
        now_unix_millis: u64,
    ) -> Result<PendingCredentialHttpAdmission, ProviderCredentialEnrollmentHostError> {
        let entry = self.take_entry(command.native_intent_id(), now_unix_millis)?;
        let binding = ProviderCredentialBeginIntentBinding::new(command, &entry.context);
        if entry.protected_session_id != protected_session_id
            || entry.action_provider_revision != *binding.action_provider_revision_digest()
            || entry.command_identity != *binding.command_identity_digest()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(entry)
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
