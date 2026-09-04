use ed25519_dalek::{Signature, VerifyingKey};

const KILL_READY: &[u8] = b"gocode/provider-credential-broker/kill-ready/v1\0";
const KILL_RELINQUISHED: &[u8] = b"gocode/provider-credential-broker/kill-relinquished/v1\0";

/// Exact authenticated writer tuple required for macOS kill handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCredentialBrokerKillBindingV1 {
    start: [u8; 32],
    image: [u8; 32],
    release: [u8; 32],
    channel: [u8; 32],
    key: [u8; 32],
    writer_kill_public_key: [u8; 32],
}

impl ProviderCredentialBrokerKillBindingV1 {
    #[must_use]
    pub const fn new(
        start: [u8; 32],
        image: [u8; 32],
        release: [u8; 32],
        channel: [u8; 32],
        key: [u8; 32],
        writer_kill_public_key: [u8; 32],
    ) -> Self {
        Self {
            start,
            image,
            release,
            channel,
            key,
            writer_kill_public_key,
        }
    }
    fn valid(&self) -> bool {
        [
            self.start,
            self.image,
            self.release,
            self.channel,
            self.key,
            self.writer_kill_public_key,
        ]
            .into_iter()
            .all(|value| value != [0; 32])
    }

    /// Reports whether every field needed by the native ownership tuple exists.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.valid()
    }
    fn transcript(&self, tag: &[u8]) -> Vec<u8> {
        let mut value = tag.to_vec();
        for field in [
            self.start,
            self.image,
            self.release,
            self.channel,
            self.key,
            self.writer_kill_public_key,
        ] {
            value.extend_from_slice(&field);
        }
        value
    }

    /// Exact transcript that only the admitted Desktop writer may sign.
    #[must_use]
    pub fn relinquishment_transcript(&self) -> Vec<u8> {
        self.transcript(KILL_RELINQUISHED)
    }

    /// Exact transcript authenticated only after native peer capture.
    #[must_use]
    pub fn ready_transcript(&self) -> Vec<u8> {
        self.transcript(KILL_READY)
    }
}

include!("broker_transfer_digest.rs");
/// Desktop proof that it relinquished all signal paths and retained reap only.
///
/// ```compile_fail
/// fn bypass(
///     authenticator: &runne_api::CredentialBrokerTransferAuthenticator,
///     binding: runne_api::ProviderCredentialBrokerKillBindingV1,
/// ) {
///     let _ = authenticator.issue_kill_relinquished(binding);
/// }
/// ```
pub struct ProviderCredentialBrokerKillRelinquishedProof {
    binding: ProviderCredentialBrokerKillBindingV1,
    signature: [u8; 64],
}

impl ProviderCredentialBrokerTransferAuthority {
    #[must_use]
    fn verifies_kill_relinquished(
        &self,
        proof: &ProviderCredentialBrokerKillRelinquishedProof,
        binding: &ProviderCredentialBrokerKillBindingV1,
    ) -> bool {
        proof.binding == *binding
            && binding.valid()
            && VerifyingKey::from_bytes(&binding.writer_kill_public_key)
                .and_then(|key| {
                    key.verify_strict(
                        &binding.relinquishment_transcript(),
                        &Signature::from_bytes(&proof.signature),
                    )
                })
                .is_ok()
    }

}

impl ProviderCredentialBrokerKillRelinquishedProof {
    /// Wraps an exact writer-key signature for later daemon verification.
    #[must_use]
    pub fn from_writer_signature(
        binding: ProviderCredentialBrokerKillBindingV1,
        signature: [u8; 64],
    ) -> ProviderCredentialBrokerKillRelinquishedProof {
        ProviderCredentialBrokerKillRelinquishedProof { binding, signature }
    }
}

impl std::fmt::Debug for ProviderCredentialBrokerKillRelinquishedProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderCredentialBrokerKillRelinquishedProof(<authenticated>)")
    }
}

/// Process-local witness for the exact request-authority issuer domain.
pub struct ProviderCredentialBrokerHandoffWitness {
    seal: Arc<AuthoritySeal>,
}

/// Move-only broker transfer authority sealed by the daemon request issuer.
pub struct ProviderCredentialBrokerTransferAuthority {
    seal: Arc<AuthoritySeal>,
    transfer_seal: Arc<AuthoritySeal>,
    protected_session_binding: [u8; 32],
    authenticator: CredentialBrokerTransferAuthenticator,
    writer_evidence_available: bool,
}

impl ProviderCredentialRequestAuthorityIssuer {
    /// Consumes one protected admission and seals its transfer key to this issuer.
    pub fn issue_from_verified_enrollment_with_broker_transfer(
        &self,
        request: VerifiedProtectedCredentialEnrollmentRequest,
        admission: ProtectedCredentialBrokerTransferAdmission,
    ) -> Result<
        (
            ProviderCredentialBaseRequestAuthority,
            ProviderCredentialIntentConsumptionProof,
            ProviderCredentialBrokerTransferAuthority,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let (admission, authenticator) = admission.into_parts();
        let protected_session_binding = admission.protected_session_binding();
        let (authority, proof) = self.issue_from_verified_enrollment(request, admission)?;
        Ok((
            authority,
            proof,
            ProviderCredentialBrokerTransferAuthority {
                seal: Arc::clone(&self.seal),
                transfer_seal: Arc::new(AuthoritySeal),
                protected_session_binding,
                authenticator,
                writer_evidence_available: true,
            },
        ))
    }
}

impl ProviderCredentialBaseRequestAuthority {
    /// Retains only the opaque issuer domain needed by a later daemon handoff.
    #[must_use]
    pub fn credential_broker_handoff_witness(&self) -> ProviderCredentialBrokerHandoffWitness {
        ProviderCredentialBrokerHandoffWitness {
            seal: Arc::clone(&self.seal),
        }
    }
}

impl ProviderCredentialBrokerHandoffWitness {
    /// Rejects a substituted current base authority from another issuer domain.
    #[must_use]
    pub fn matches_authority(&self, authority: &ProviderCredentialBaseRequestAuthority) -> bool {
        Arc::ptr_eq(&self.seal, &authority.seal)
    }
}

impl ProviderCredentialBrokerTransferAuthority {
    /// Mints the daemon-side transfer authority for one exact enrollment V3 launch.
    ///
    /// The same-process V2→V3 transition has no issuer/admission pair yet: the
    /// desktop and daemon share the V3 launch keys, and both derive the same
    /// broker-transfer key domain from them. Later uses stay one-shot through
    /// `writer_evidence_available` and the instance-local transfer seal.
    #[must_use]
    pub fn from_enrollment_launch_keys(
        keys: &ProtectedActivationKeys,
        commitment: &CredentialBrokerTransferCommitment,
    ) -> Self {
        Self {
            seal: Arc::new(AuthoritySeal),
            transfer_seal: Arc::new(AuthoritySeal),
            protected_session_binding: *commitment.as_bytes(),
            authenticator: CredentialBrokerTransferAuthenticator::from_protected_activation(keys),
            writer_evidence_available: true,
        }
    }

    /// Binds the transfer key to both the daemon issuer and current session.
    #[must_use]
    pub fn matches_handoff(
        &self,
        witness: &ProviderCredentialBrokerHandoffWitness,
        protected_session_binding: &[u8; 32],
    ) -> bool {
        Arc::ptr_eq(&self.seal, &witness.seal)
            && self.protected_session_binding == *protected_session_binding
    }

    /// Produces only a descriptor/evidence transfer-domain proof.
    #[must_use]
    pub fn authenticate_daemon_transfer(&self, record: &[u8]) -> [u8; 32] {
        self.authenticator.authenticate_daemon_transfer(record)
    }

    /// Verifies only a Desktop-originated descriptor/evidence proof.
    #[must_use]
    pub fn verifies_desktop_transfer(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        self.authenticator.verifies_desktop_transfer(record, proof)
    }

    /// Constructs an authority solely for isolated native-adapter tests.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_only_from_authenticator(
        authenticator: CredentialBrokerTransferAuthenticator,
    ) -> Self {
        Self {
            seal: Arc::new(AuthoritySeal),
            transfer_seal: Arc::new(AuthoritySeal),
            protected_session_binding: [1; 32],
            authenticator,
            writer_evidence_available: true,
        }
    }
}

impl fmt::Debug for ProviderCredentialBrokerTransferAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderCredentialBrokerTransferAuthority(<authenticated>)")
    }
}

include!("broker_transfer_kill_wire.rs");
include!("broker_transfer_evidence.rs");
include!("broker_handoff_context.rs");
include!("broker_handoff_control.rs");
include!("broker_recovery_transfer.rs");

#[cfg(test)]
#[path = "broker_handoff_tests.rs"]
mod broker_handoff_tests;
#[cfg(test)]
#[path = "broker_transfer_digest_tests.rs"]
mod broker_transfer_digest_tests;
