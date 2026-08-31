use core::fmt;
use std::sync::Arc;

use super::ProviderCredentialEnrollmentHostError;
use crate::{
    CredentialBrokerTransferAuthenticator, CredentialBrokerTransferCommitment,
    ProtectedCredentialBrokerTransferAdmission, VerifiedProtectedCredentialEnrollmentAdmission,
    VerifiedProtectedCredentialEnrollmentRequest,
};

struct AuthoritySeal;

/// Creates one process-local issuer/verifier domain for protected requests.
pub struct ProviderCredentialRequestAuthorityPair {
    seal: Arc<AuthoritySeal>,
}

impl ProviderCredentialRequestAuthorityPair {
    /// Creates a fresh domain. Authorities from another domain fail verification.
    pub fn new() -> Self {
        Self {
            seal: Arc::new(AuthoritySeal),
        }
    }

    /// Splits the domain between authenticated transport and daemon coordinator.
    pub fn split(
        self,
    ) -> (
        ProviderCredentialRequestAuthorityIssuer,
        ProviderCredentialRequestAuthorityVerifier,
    ) {
        (
            ProviderCredentialRequestAuthorityIssuer {
                seal: Arc::clone(&self.seal),
            },
            ProviderCredentialRequestAuthorityVerifier { seal: self.seal },
        )
    }
}

impl Default for ProviderCredentialRequestAuthorityPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Issuer injected only into the authenticated protected transport boundary.
#[derive(Clone)]
pub struct ProviderCredentialRequestAuthorityIssuer {
    seal: Arc<AuthoritySeal>,
}

/// Verifier retained by the daemon coordinator before provider/store parsing.
#[derive(Clone)]
pub struct ProviderCredentialRequestAuthorityVerifier {
    seal: Arc<AuthoritySeal>,
}

impl ProviderCredentialRequestAuthorityIssuer {
    /// Issues base authority from a complete authenticated transport binding.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_base(
        &self,
        installation_identity: [u8; 32],
        release_tuple_digest: [u8; 32],
        protected_session_id: [u8; 32],
        desktop_supervisor_generation: u64,
        daemon_authority_id: [u8; 32],
        database_generation: u64,
        authenticated_tauri_peer_process: [u8; 32],
    ) -> Result<ProviderCredentialBaseRequestAuthority, ProviderCredentialEnrollmentHostError> {
        if [
            installation_identity,
            release_tuple_digest,
            protected_session_id,
            daemon_authority_id,
            authenticated_tauri_peer_process,
        ]
        .contains(&[0; 32])
            || desktop_supervisor_generation == 0
            || database_generation == 0
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(ProviderCredentialBaseRequestAuthority {
            seal: Arc::clone(&self.seal),
            installation_identity,
            release_tuple_digest,
            protected_session_id,
            desktop_supervisor_generation,
            daemon_authority_id,
            database_generation,
            authenticated_tauri_peer_process,
        })
    }

    /// Issues a proof only after protected-session envelope authentication.
    pub fn issue_intent_proof(
        &self,
        proof_digest: [u8; 32],
        protected_session_binding: [u8; 32],
        action_provider_revision_binding: [u8; 32],
        command_identity_binding: [u8; 32],
        expires_at_high_water: i64,
    ) -> Result<ProviderCredentialIntentConsumptionProof, ProviderCredentialEnrollmentHostError>
    {
        if [
            proof_digest,
            protected_session_binding,
            action_provider_revision_binding,
            command_identity_binding,
        ]
        .contains(&[0; 32])
            || expires_at_high_water <= 0
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(ProviderCredentialIntentConsumptionProof {
            seal: Arc::clone(&self.seal),
            proof_digest,
            protected_session_binding,
            action_provider_revision_binding,
            command_identity_binding,
            expires_at_high_water,
        })
    }

    /// Consumes the verified protected enrollment claims at the authority bridge.
    ///
    /// The by-value API prevents accidental reuse of the verified envelope in the
    /// caller. Durable one-use admission consumption and replay CAS remain the
    /// daemon/store owner's responsibility before this bridge is invoked.
    pub fn issue_from_verified_enrollment(
        &self,
        request: VerifiedProtectedCredentialEnrollmentRequest,
        admission: VerifiedProtectedCredentialEnrollmentAdmission,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialIntentConsumptionProof,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        if request.request_digest() != admission.request_digest()
            || request.request_id() != admission.request_id()
            || request.sequence().checked_add(1) != Some(admission.sequence())
            || request.request_proof_binding() != admission.request_proof_binding()
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }

        let expires_at_high_water = i64::try_from(admission.expires_at_unix_millis() / 1_000)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?
            .max(0);
        if expires_at_high_water == 0 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let authority = self.issue_base(
            admission.installation_identity(),
            admission.release_tuple_digest(),
            admission.protected_session_binding(),
            admission.desktop_supervisor_generation(),
            admission.daemon_authority_binding(),
            admission.database_generation(),
            admission.authenticated_tauri_peer_binding(),
        )?;
        let proof = self.issue_intent_proof(
            request.request_digest(),
            admission.protected_session_binding(),
            request.action_provider_revision_binding(),
            request.command_identity_binding(),
            expires_at_high_water,
        )?;
        Ok((authority, proof))
    }
}

impl ProviderCredentialRequestAuthorityVerifier {
    /// Rejects authorities minted outside this coordinator's paired issuer.
    pub fn verify_base(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        verify_seal(&self.seal, &authority.seal)
    }

    /// Rejects intent proofs minted outside this coordinator's paired issuer.
    pub fn verify_intent_proof(
        &self,
        proof: &ProviderCredentialIntentConsumptionProof,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        verify_seal(&self.seal, &proof.seal)
    }
}

fn verify_seal(
    expected: &Arc<AuthoritySeal>,
    actual: &Arc<AuthoritySeal>,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    if Arc::ptr_eq(expected, actual) {
        Ok(())
    } else {
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

/// Server-derived authority required before any provider/store parsing.
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_api::ProviderCredentialBaseRequestAuthority>();
/// ```
///
/// ```compile_fail
/// let _ = runne_api::ProviderCredentialBaseRequestAuthority::new();
/// ```
pub struct ProviderCredentialBaseRequestAuthority {
    seal: Arc<AuthoritySeal>,
    installation_identity: [u8; 32],
    release_tuple_digest: [u8; 32],
    protected_session_id: [u8; 32],
    desktop_supervisor_generation: u64,
    daemon_authority_id: [u8; 32],
    database_generation: u64,
    authenticated_tauri_peer_process: [u8; 32],
}

impl ProviderCredentialBaseRequestAuthority {
    pub const fn installation_identity(&self) -> &[u8; 32] {
        &self.installation_identity
    }
    pub const fn release_tuple_digest(&self) -> &[u8; 32] {
        &self.release_tuple_digest
    }
    pub const fn protected_session_id(&self) -> &[u8; 32] {
        &self.protected_session_id
    }
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.desktop_supervisor_generation
    }
    pub const fn daemon_authority_id(&self) -> &[u8; 32] {
        &self.daemon_authority_id
    }
    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }
    pub const fn authenticated_tauri_peer_process(&self) -> &[u8; 32] {
        &self.authenticated_tauri_peer_process
    }
}

impl fmt::Debug for ProviderCredentialBaseRequestAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCredentialBaseRequestAuthority(<authenticated>)")
    }
}

/// Authenticated one-time native-intent consumption proof for begin or verify.
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_api::ProviderCredentialIntentConsumptionProof>();
/// ```
pub struct ProviderCredentialIntentConsumptionProof {
    seal: Arc<AuthoritySeal>,
    proof_digest: [u8; 32],
    protected_session_binding: [u8; 32],
    action_provider_revision_binding: [u8; 32],
    command_identity_binding: [u8; 32],
    expires_at_high_water: i64,
}

impl ProviderCredentialIntentConsumptionProof {
    pub const fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }
    pub const fn protected_session_binding(&self) -> &[u8; 32] {
        &self.protected_session_binding
    }
    pub const fn action_provider_revision_binding(&self) -> &[u8; 32] {
        &self.action_provider_revision_binding
    }
    pub const fn command_identity_binding(&self) -> &[u8; 32] {
        &self.command_identity_binding
    }
    pub const fn expires_at_high_water(&self) -> i64 {
        self.expires_at_high_water
    }
}

impl fmt::Debug for ProviderCredentialIntentConsumptionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCredentialIntentConsumptionProof(<authenticated>)")
    }
}

include!("authority/broker_transfer.rs");
