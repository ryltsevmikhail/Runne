//! Linux writer authority for the daemon broker channel (M6 step 1).
//!
//! Mirrors `VerifiedMacOsWriterWithDaemonKillCapability` with the accepted
//! Linux fact sources: the pidfd-retained writer process (exact kill/reap
//! ownership), the measured `VerifiedLinuxWriterAdmission` facts (pinned
//! image digest + live start identity), and the SAME attestation claims
//! built by the neutral `attestation_claims` builder. `release_tuple`
//! carries the approved LOCAL content pin (activation-record binding), never
//! a signer identity. Ticket one-use/TTL/replay remain in the registry.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the D1 Linux composition slice mounts the pidfd writer broker; tests drive it today"
    )
)]

use std::os::unix::net::UnixStream;

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner;
use runne_provider::{
    CredentialBrokerFrame, IssuedCredentialTicketAttempt,
    SignedCredentialWriterSessionAttestationV1,
};

use super::super::pending::PendingBrokerRendezvousBinding;
use super::super::rendezvous::DaemonBrokerAuthority;
use super::attestation_claims::{SessionClaimInputs, build_session_claims};

/// Startup-authenticated writer process facts bound into the durable claim:
/// (start identity, pinned image digest, verified kill publication key).
pub(crate) type WriterProcessFacts = ([u8; 32], [u8; 32], [u8; 32]);

/// Daemon identity and qualified-session material for one V2 session signing.
pub(crate) struct QualifiedWriterSessionMaterial {
    pub(crate) daemon_start: [u8; 32],
    pub(crate) daemon_image: [u8; 32],
    pub(crate) launch_generation: u64,
    pub(crate) context_sha256: [u8; 32],
    pub(crate) ticket_sha256: [u8; 32],
}

/// Exact Linux writer retained by the daemon: pidfd-owned process, measured
/// admission facts, one channel authority.
pub(crate) struct VerifiedLinuxWriterWithDaemonAuthority {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    process: runne_platform_desktop::UnixRetainedWriterProcess,
    admission: runne_platform_desktop::provider_credential_broker::linux_writer_admission::VerifiedLinuxWriterAdmission,
    /// MISSING HANDSHAKE FIELD: the authenticated writer kill publication
    /// key. No verified Linux handoff delivers it yet (pidfd owns kill
    /// locally, but the attestation slot must carry a real key, never the
    /// channel binding or the start identity). `None` fails every session
    /// signing closed until the B8 wire receiver supplies the verified key.
    kill_public_key: Option<[u8; 32]>,
}

impl VerifiedLinuxWriterWithDaemonAuthority {
    /// Combines the reserved broker authority with an admitted, pidfd-owned
    /// writer process. The admission facts must already be verified against
    /// the pinned launch spec (`admit_linux_writer`); nothing here re-mints
    /// authority — the endpoint/signer pair comes from the daemon rendezvous.
    /// `writer_kill_public_key` must eventually come from the verified Linux
    /// writer handshake; passing `None` keeps every attestation fail-closed.
    pub(in crate::application::provider_credential_enrollment::broker) const fn from_admitted_parts(
        binding: PendingBrokerRendezvousBinding,
        authority: DaemonBrokerAuthority,
        process: runne_platform_desktop::UnixRetainedWriterProcess,
        admission: runne_platform_desktop::provider_credential_broker::linux_writer_admission::VerifiedLinuxWriterAdmission,
        writer_kill_public_key: Option<[u8; 32]>,
    ) -> Self {
        Self {
            binding,
            authority,
            process,
            admission,
            kill_public_key: writer_kill_public_key,
        }
    }

    /// The authenticated kill publication key, or a closed failure while the
    /// Linux handshake does not yet deliver one.
    fn kill_public_key(
        &self,
    ) -> Result<[u8; 32], runne_api::ProviderCredentialEnrollmentHostError> {
        self.kill_public_key
            .ok_or(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    pub(in crate::application::provider_credential_enrollment::broker) fn control(
        &mut self,
    ) -> &mut UnixStream {
        self.authority.endpoint_mut_linux()
    }

    /// The rendezvous binding this exact writer was admitted against.
    #[expect(
        dead_code,
        reason = "reserved for the D1 composition slice's channel binding check"
    )]
    pub(in crate::application::provider_credential_enrollment::broker) const fn binding(
        &self,
    ) -> &PendingBrokerRendezvousBinding {
        &self.binding
    }

    /// Startup-authenticated writer facts used to bind the durable claim.
    pub(crate) fn claim_process_facts(
        &self,
    ) -> Result<WriterProcessFacts, ProviderCredentialEnrollmentHostError> {
        Ok((
            self.admission.start_identity(),
            self.admission.image_digest(),
            self.kill_public_key()?,
        ))
    }

    pub(crate) const fn channel_binding(&self) -> [u8; 32] {
        self.authority.channel_binding()
    }

    pub(crate) fn sign_writer_session(
        &mut self,
        receipt: &IssuedCredentialTicketAttempt,
        frame: &CredentialBrokerFrame,
        daemon_start: [u8; 32],
        daemon_image: [u8; 32],
    ) -> Result<
        (
            SignedCredentialWriterSessionAttestationV1,
            CredentialSecretPublicationSigner,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let inputs = SessionClaimInputs {
            owner: self.binding.owner,
            begin_proof: self.binding.begin_proof,
            protected_session: self.binding.protected_session,
            tauri_peer: self.binding.tauri_peer,
            daemon_authority: self.binding.daemon_authority,
            database_generation: self.binding.database_generation,
            supervisor_generation: self.binding.supervisor_generation,
            release_tuple: self.binding.release_tuple,
            endpoint_handoff_digest: self.channel_binding(),
            writer_process_start: self.admission.start_identity(),
            writer_image: self.admission.image_digest(),
            writer_kill_public_key: self.kill_public_key()?,
        };
        let claims = build_session_claims(receipt, frame, daemon_start, daemon_image, &inputs)?;
        self.authority.sign_writer_session(claims)
    }

    /// One measured V2 session: attests the qualified issue against the exact
    /// pidfd-retained writer, then hands back the prelude signer.
    #[expect(
        dead_code,
        reason = "reserved for the D1 composition slice's qualified exchange"
    )]
    pub(crate) fn sign_writer_session_qualified(
        &mut self,
        receipt: &IssuedCredentialTicketAttempt,
        frame: &CredentialBrokerFrame,
        material: &QualifiedWriterSessionMaterial,
    ) -> Result<
        (
            runne_provider::SignedCredentialWriterSessionAttestationV2,
            runne_provider::CredentialWriterQualifiedPreludeSigner,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        let QualifiedWriterSessionMaterial {
            daemon_start,
            daemon_image,
            launch_generation,
            context_sha256,
            ticket_sha256,
        } = *material;
        let inputs = SessionClaimInputs {
            owner: self.binding.owner,
            begin_proof: self.binding.begin_proof,
            protected_session: self.binding.protected_session,
            tauri_peer: self.binding.tauri_peer,
            daemon_authority: self.binding.daemon_authority,
            database_generation: self.binding.database_generation,
            supervisor_generation: self.binding.supervisor_generation,
            release_tuple: self.binding.release_tuple,
            endpoint_handoff_digest: self.channel_binding(),
            writer_process_start: self.admission.start_identity(),
            writer_image: self.admission.image_digest(),
            writer_kill_public_key: self.kill_public_key()?,
        };
        let claims = build_session_claims(receipt, frame, daemon_start, daemon_image, &inputs)?;
        self.authority.sign_writer_session_qualified(
            claims,
            launch_generation,
            context_sha256,
            ticket_sha256,
        )
    }

    /// Terminates and reaps exactly the retained pidfd-owned writer.
    pub(crate) fn terminate_exact_writer(
        mut self,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
        self.process
            .terminate_retained_child()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        self.process
            .reap_retained_child()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
    }
}
