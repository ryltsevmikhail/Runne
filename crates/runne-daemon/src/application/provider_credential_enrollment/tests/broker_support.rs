use std::{
    collections::VecDeque,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
use runne_provider::{
    BeginCredentialOperation, BeginCredentialOperationOutcome, ClaimCredentialOperation,
    CredentialAuthorityPair, CredentialBrokerCommand, CredentialEnrollmentAuthorityPair,
    CredentialFence, CredentialLifecycleRevision, CredentialMeasurementSnapshot,
    CredentialOperationAction, CredentialOperationId, CredentialSecretClaimOffer,
    CredentialWriterSessionAttestationClaimsV1, ProviderCredentialEnrollmentStore, ProviderId,
};
use zeroize::Zeroizing;

use super::super::broker::issue::ClaimIssueContext;
use super::super::broker::writer_session_test_support::writer_session_claims;
use super::super::broker::{CredentialBrokerChannel, ProviderCredentialBroker};

pub(crate) struct Fixture {
    pub(crate) enrollment_authority: runne_provider::CredentialEnrollmentStoreAuthority,
    pub(crate) broker: ProviderCredentialBroker,
    pub(crate) measurements: Arc<runne_provider::CredentialEnrollmentMeasurementAuthority>,
    pub(crate) store: runne_store::provider::SqliteProviderCredentialLifecycleStore,
    pub(crate) operation: runne_provider::CredentialOperationSnapshot,
    pub(crate) continuation: runne_provider::CredentialBindingDigest,
    _directory: tempfile::TempDir,
}

pub(crate) fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let measurements = Arc::new(measurements);
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("broker.sqlite"),
            lifecycle,
            enrollment.clone(),
        )
        .unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let qualified = measurements
        .issue_qualified_credential_release_tuple(
            measurements.release_manifest_digest([9; 32]).unwrap(),
        )
        .unwrap();
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let operation = match store
        .begin(
            BeginCredentialOperation::new(
                CommandId::from_bytes([1; 16]),
                IdempotencyKey::new("broker-ticket").unwrap(),
                CredentialOperationId::from_bytes([2; 16]).unwrap(),
                runne_provider::CredentialInstallationOwnerId::from_bytes([3; 32]).unwrap(),
                provider.clone(),
                CredentialOperationAction::Pair,
                Some(runne_provider::CredentialVersionRef::new(provider, 1).unwrap()),
                None,
                CredentialLifecycleRevision::new(1).unwrap(),
                CredentialFence::new(1).unwrap(),
                runne_provider::CredentialBindingDigest::from_measured([4; 32]).unwrap(),
                expiration,
            )
            .unwrap()
            .with_qualified_release_tuple(qualified),
        )
        .unwrap()
    {
        BeginCredentialOperationOutcome::FreshWinner(value) => value,
        BeginCredentialOperationOutcome::ExactReplay(_) => panic!("first begin must win"),
    };
    Fixture {
        enrollment_authority: enrollment,
        broker: ProviderCredentialBroker::new(measurements.clone()),
        measurements,
        store,
        operation,
        continuation: runne_provider::CredentialBindingDigest::from_measured([5; 32]).unwrap(),
        _directory: directory,
    }
}

pub(crate) fn issue_context(fixture: &Fixture) -> ClaimIssueContext {
    issue_context_for(fixture, fixture.continuation)
}

pub(crate) fn issue_context_for(
    fixture: &Fixture,
    continuation: runne_provider::CredentialBindingDigest,
) -> ClaimIssueContext {
    fixture
        .broker
        .claim_issue_context(
            claim_measurements_for(&fixture.measurements, continuation, 8),
            [21; 32],
            continuation,
            7,
            8,
        )
        .unwrap()
}

pub(crate) fn claim_measurements(
    authority: &runne_provider::CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
) -> CredentialMeasurementSnapshot {
    claim_measurements_for(
        authority,
        claim.continuation_binding_digest(),
        claim.desktop_supervisor_generation(),
    )
}

pub(crate) fn claim_measurements_for(
    authority: &runne_provider::CredentialEnrollmentMeasurementAuthority,
    continuation: runne_provider::CredentialBindingDigest,
    desktop_supervisor_generation: u64,
) -> CredentialMeasurementSnapshot {
    CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([10; 32]).unwrap(),
        authority.release_manifest_digest([11; 32]).unwrap(),
        authority.desktop_executable_identity([12; 32]).unwrap(),
        authority.writer_executable_identity([13; 32]).unwrap(),
        authority.reader_executable_identity([14; 32]).unwrap(),
        authority.contract_bundle_digest([15; 32]).unwrap(),
        authority.daemon_authority_id([16; 32]).unwrap(),
        authority.protected_session_id([17; 32]).unwrap(),
        authority
            .desktop_supervisor_generation(desktop_supervisor_generation)
            .unwrap(),
        authority.writer_launch_id([18; 32]).unwrap(),
        authority.writer_process_start_identity([19; 32]).unwrap(),
        authority.writer_process_handle_identity([20; 32]).unwrap(),
        authority.broker_channel_binding([21; 32]).unwrap(),
        authority
            .continuation_binding_digest(continuation.as_bytes())
            .unwrap(),
    )
    .unwrap()
}

pub(crate) struct RecordingChannel {
    pub(crate) frames: Vec<Vec<u8>>,
    received: VecDeque<Zeroizing<Vec<u8>>>,
    fail_send: bool,
    binding: runne_provider::CredentialBindingDigest,
    attestation_signer: Option<CredentialWriterSessionAttestationSigner>,
    attestation_claims: Option<CredentialWriterSessionAttestationClaimsV1>,
    publication_public_key: [u8; 32],
    pub(crate) sign_invocations: u8,
    pub(crate) receive_calls: u8,
}

impl RecordingChannel {
    pub(crate) fn with_channel_binding(binding: [u8; 32]) -> Self {
        let signer = CredentialWriterSessionAttestationSigner::generate(binding).unwrap();
        let publication_public_key = signer.public_key();
        Self {
            frames: Vec::new(),
            received: VecDeque::new(),
            fail_send: false,
            binding: runne_provider::CredentialBindingDigest::from_measured(binding).unwrap(),
            attestation_signer: Some(signer),
            attestation_claims: None,
            publication_public_key,
            sign_invocations: 0,
            receive_calls: 0,
        }
    }

    pub(crate) fn queue_received(&mut self, frame: Zeroizing<Vec<u8>>) {
        self.received.push_back(frame);
    }

    pub(crate) fn fail_next_send(&mut self) {
        self.fail_send = true;
    }

    pub(crate) const fn publication_public_key(&self) -> [u8; 32] {
        self.publication_public_key
    }
}

impl Default for RecordingChannel {
    fn default() -> Self {
        Self::with_channel_binding([21; 32])
    }
}

impl CredentialBrokerChannel for RecordingChannel {
    fn binding_digest(&self) -> runne_provider::CredentialBindingDigest {
        self.binding
    }

    fn send_issue(
        &mut self,
        _receipt: &runne_provider::IssuedCredentialTicketAttempt,
        frame: runne_provider::CredentialBrokerFrame,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let encoded = runne_provider::CredentialBrokerFrameCodec::encode(frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.send(Zeroizing::new(encoded))
    }

    fn send(
        &mut self,
        frame: Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if std::mem::take(&mut self.fail_send) {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        let decoded = runne_provider::CredentialBrokerFrameCodec::decode(&frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        if matches!(
            decoded,
            runne_provider::CredentialBrokerFrame::IssueTicket { .. }
        ) {
            self.attestation_claims = Some(
                writer_session_claims(&decoded)
                    .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
            );
        }
        self.frames.push(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, ProviderCredentialEnrollmentHostError> {
        self.receive_calls = self.receive_calls.saturating_add(1);
        self.received
            .pop_front()
            .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)
    }

    fn sign_publication(
        &mut self,
        offer: CredentialSecretClaimOffer,
    ) -> Result<runne_provider::CredentialSecretPublication, ProviderCredentialEnrollmentHostError>
    {
        let signer = self
            .attestation_signer
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let claims = self
            .attestation_claims
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let (_, signer) = signer
            .sign(claims)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.sign_invocations = self.sign_invocations.saturating_add(1);
        signer
            .sign(offer, self.binding)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

pub(crate) fn pair_offer(
    receipt: &runne_provider::IssuedCredentialTicketAttempt,
    binding: runne_provider::CredentialBindingDigest,
) -> CredentialSecretClaimOffer {
    let command =
        CredentialBrokerCommand::from_operation(receipt.operation(), receipt.ticket_attempt())
            .unwrap();
    CredentialSecretClaimOffer::prepare(&command, binding)
        .unwrap()
        .0
}
