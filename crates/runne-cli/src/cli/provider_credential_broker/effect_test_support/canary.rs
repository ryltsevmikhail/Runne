use std::io::Cursor;
use std::sync::{Arc, Mutex};

use runne_provider::{
    ClaimedWriterAuthorization, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialEnrollmentAuthorityPair, CredentialOperationAction,
    CredentialSecretInputPresence, CredentialWriterAuthorityPair, NativeCredentialDeletionProof,
    PendingCredentialIssueTicketV1, PendingCredentialSecretOpening, RawCredentialTicket,
    SealedCredentialEnvelope,
};
use runne_secure_store::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredProviderCredentialWriter,
    BrokeredWriterIdentityMigrationInput, BrokeredWriterIdentityVerificationInput,
    SecureStoreError, WriterIdentityMigrationObservation,
};

use super::super::claim::{
    ClaimedWriterControl, claim_writer_authorization_with_legacy_parts,
};
use super::{TestControl, command};

pub struct PanickingPairClaimFixture {
    pub claimed: ClaimedWriterControl,
    pub written: Arc<Mutex<Vec<u8>>>,
}

pub fn panicking_pair_claimed_with_ticket(
    ticket_bytes: [u8; 32],
    released: bool,
) -> PanickingPairClaimFixture {
    let command = command(CredentialOperationAction::Pair);
    let binding = CredentialBindingDigest::from_measured([13; 32]).expect("binding");
    let ticket = RawCredentialTicket::generate_with_test_entropy(|output| {
        *output = ticket_bytes;
        Ok(())
    })
    .expect("deterministic ticket");
    let mut encoded_ticket = Vec::new();
    CredentialBrokerFrameCodec::write_to(
        &mut encoded_ticket,
        CredentialBrokerFrame::IssueTicket {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            ticket,
            channel_binding: [11; 32],
            binding,
            command: command.clone(),
        },
    )
    .expect("issue");
    let ticket = PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(encoded_ticket))
        .expect("pending ticket");
    let mut input = Vec::new();
    CredentialBrokerFrameCodec::write_to(
        &mut input,
        CredentialBrokerFrame::ClaimAccepted {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
        },
    )
    .expect("ack");
    if released {
        CredentialBrokerFrameCodec::write_to(
            &mut input,
            CredentialBrokerFrame::NativeEffectRelease {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
                binding,
            },
        )
        .expect("release");
    }
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([11; 32]).expect("channel");
    let written = Arc::new(Mutex::new(Vec::new()));
    let writer: Arc<dyn BrokeredProviderCredentialWriter> = Arc::new(PanickingWriter);
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    let claimed = claim_writer_authorization_with_legacy_parts(
        TestControl::new(input, written.clone(), false),
        channel,
        ticket,
        &issuer,
        writer,
        CredentialSecretInputPresence::Present,
    )
    .expect("pair claim");
    PanickingPairClaimFixture { claimed, written }
}

struct PanickingWriter;

impl BrokeredProviderCredentialWriter for PanickingWriter {
    fn create_sealed_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredCreateInput,
        _pending: PendingCredentialSecretOpening,
        _envelope: SealedCredentialEnvelope,
    ) -> Result<(), SecureStoreError> {
        panic!("controlled writer panic")
    }

    fn delete_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredDeleteInput,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn import_legacy_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredMigrateLegacyInput,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn delete_legacy_source_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn migrate_writer_identity_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredWriterIdentityMigrationInput,
    ) -> Result<WriterIdentityMigrationObservation, SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn verify_writer_identity_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredWriterIdentityVerificationInput,
    ) -> Result<WriterIdentityMigrationObservation, SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }
}
