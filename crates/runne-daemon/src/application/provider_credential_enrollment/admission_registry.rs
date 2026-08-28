use std::collections::HashMap;
use std::sync::Mutex;

use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentHostError, ProviderCredentialIntentConsumptionProof,
    ProviderCredentialRequestAuthorityIssuer, VerifiedProtectedCredentialEnrollmentAdmission,
    VerifiedProtectedCredentialEnrollmentRequest, protected_credential_native_intent_digest,
};

const MAX_PENDING_ADMISSIONS: usize = 64;

/// Daemon-owned one-use bridge from protected control to a V2 HTTP request.
///
/// The registry retains only a native-intent digest and non-Serde values. A
/// matching HTTP handoff removes the entry before returning authority material.
#[allow(dead_code)]
pub(crate) struct PendingCredentialHttpAdmissions {
    issuer: ProviderCredentialRequestAuthorityIssuer,
    entries: Mutex<HashMap<[u8; 32], PendingCredentialHttpAdmission>>,
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
    pub(crate) fn new(issuer: ProviderCredentialRequestAuthorityIssuer) -> Self {
        Self {
            issuer,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Registers one fully verified protected-control admission.
    pub(crate) fn register(
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
        let (authority, proof) = self
            .issuer
            .issue_from_verified_enrollment(request, admission)?;
        let entry = PendingCredentialHttpAdmission {
            protected_session_id,
            action_provider_revision,
            command_identity,
            expires_at_unix_millis,
            authority,
            proof,
            context,
        };
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        entries.retain(|_, value| value.expires_at_unix_millis > now_unix_millis);
        if entries.contains_key(&native_intent_digest) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        if entries.len() >= MAX_PENDING_ADMISSIONS {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        entries.insert(native_intent_digest, entry);
        Ok(())
    }

    /// Consumes the exact admission bound to a live session and V2 command.
    pub(crate) fn take(
        &self,
        native_intent_id: &str,
        protected_session_id: [u8; 16],
        action_provider_revision: [u8; 32],
        command_identity: [u8; 32],
        now_unix_millis: u64,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialIntentConsumptionProof,
            ProviderCredentialCommandContext,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        if now_unix_millis == 0 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let native_intent_digest = protected_credential_native_intent_digest(native_intent_id);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        entries.retain(|_, value| value.expires_at_unix_millis > now_unix_millis);
        let entry = entries
            .remove(&native_intent_digest)
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if entry.expires_at_unix_millis <= now_unix_millis
            || entry.protected_session_id != protected_session_id
            || entry.action_provider_revision != action_provider_revision
            || entry.command_identity != command_identity
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok((entry.authority, entry.proof, entry.context))
    }
}

#[cfg(test)]
mod tests {
    use runne_api::{
        ApiActor, ApiPrincipalId, LaunchSecret, ProtectedCredentialEnrollmentAdmissionBinding,
        ProtectedCredentialEnrollmentAuthenticator, ProtectedCredentialEnrollmentControlFrame,
        ProtectedCredentialEnrollmentRequestBinding, ProviderCredentialCommandContext,
        ProviderCredentialRequestAuthorityPair,
    };
    use runne_domain::id::{CommandId, IdempotencyKey};

    use super::*;

    #[test]
    fn pending_admission_requires_the_exact_native_intent_session_and_claims_once() {
        let (registry, request, admission) = verified_admission();
        registry
            .register(request, admission, context(), 100_000)
            .unwrap();

        assert!(
            registry
                .take("intent-b", uuid(2), [8; 32], [9; 32], 110_000)
                .is_err()
        );
        assert!(
            registry
                .take("intent-a", uuid(2), [8; 32], [9; 32], 110_000)
                .is_ok()
        );
        assert!(
            registry
                .take("intent-a", uuid(2), [8; 32], [9; 32], 110_000)
                .is_err()
        );
    }

    #[test]
    fn matching_intent_with_substituted_claim_consumes_the_admission() {
        let (registry, request, admission) = verified_admission();
        registry
            .register(request, admission, context(), 100_000)
            .unwrap();

        assert!(
            registry
                .take("intent-a", uuid(2), [8; 32], [10; 32], 110_000)
                .is_err()
        );
        assert!(
            registry
                .take("intent-a", uuid(2), [8; 32], [9; 32], 110_000)
                .is_err()
        );
    }

    fn verified_admission() -> (
        PendingCredentialHttpAdmissions,
        VerifiedProtectedCredentialEnrollmentRequest,
        VerifiedProtectedCredentialEnrollmentAdmission,
    ) {
        let keys = LaunchSecret::from_bytes([1; 32]).unwrap().derive_keys();
        let authenticator =
            ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
        let request_binding = ProtectedCredentialEnrollmentRequestBinding::new(
            uuid(1),
            uuid(2),
            uuid(3),
            3,
            2,
            uuid(4),
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            protected_credential_native_intent_digest("intent-a"),
            [8; 32],
            [9; 32],
            100_000,
            120_000,
        )
        .unwrap();
        let request_frame = ProtectedCredentialEnrollmentControlFrame::Request(
            authenticator
                .issue_request(request_binding.clone(), 1)
                .unwrap(),
        )
        .encode_frame();
        let request = authenticator
            .decode_request(&request_frame, &request_binding, 0, 110_000)
            .unwrap();
        let admission_binding = ProtectedCredentialEnrollmentAdmissionBinding::new(
            [10; 32],
            [4; 32],
            [11; 32],
            2,
            [12; 32],
            4,
            [5; 32],
            [6; 32],
            [7; 32],
            uuid(5),
            120_000,
        )
        .unwrap();
        let admission_frame = ProtectedCredentialEnrollmentControlFrame::Admission(
            authenticator
                .issue_admission(&request, admission_binding.clone(), 2)
                .unwrap(),
        )
        .encode_frame();
        let admission = authenticator
            .decode_admission(&admission_frame, &request, &admission_binding, 1, 110_000)
            .unwrap();
        let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
        (
            PendingCredentialHttpAdmissions::new(issuer),
            request,
            admission,
        )
    }

    fn context() -> ProviderCredentialCommandContext {
        ProviderCredentialCommandContext {
            command_id: CommandId::from_bytes([1; 16]),
            idempotency_key: IdempotencyKey::new("credential-admission").unwrap(),
            principal: ApiPrincipalId::new("credential-principal").unwrap(),
            actor: ApiActor::new("credential-host").unwrap(),
        }
    }

    fn uuid(value: u8) -> [u8; 16] {
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
    }
}
