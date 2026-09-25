use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};

use runne_provider::{
    ClaimedWriterAuthorization, CredentialBindingDigest, CredentialBrokerCommand,
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialBrokerTarget,
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialSecretInputPresence,
    CredentialTicketAttempt, CredentialVersionRef, CredentialWriterAuthorityPair,
    NativeCredentialDeletionProof, PendingCredentialIssueTicketV1, PendingCredentialSecretOpening,
    ProviderId, RawCredentialTicket, SealedCredentialEnvelope, WriterIdentityMigrationPhase,
};
use runne_secure_store::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredProviderCredentialWriter,
    BrokeredWriterIdentityMigrationInput, BrokeredWriterIdentityVerificationInput,
    SecureStoreError, WriterIdentityMigrationObservation,
};

use super::claim::{ClaimedWriterControl, claim_writer_authorization_with_legacy_parts};
#[path = "effect_test_support/pair.rs"]
mod pair;
#[path = "effect_test_support/release.rs"]
mod release;
pub use pair::{
    pair_authorized, pair_authorized_with_diagnostic_failure, pair_claimed,
    pair_claimed_successfully, pair_claimed_with_release,
};
#[path = "effect_test_support/canary.rs"]
mod canary;
pub use canary::panicking_pair_claimed_with_ticket;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectCall {
    Create,
    Delete,
    ImportLegacy,
    DeleteLegacySource,
}

pub struct ClaimFixture {
    pub claimed: ClaimedWriterControl,
    pub calls: Arc<Mutex<Vec<EffectCall>>>,
    pub written: Arc<Mutex<Vec<u8>>>,
}

pub fn claimed(action: CredentialOperationAction) -> ClaimFixture {
    let command = command(action);
    let (control, channel, ticket, written) = endpoint(&command, false);
    claimed_from_parts(control, channel, ticket, written, action)
}

pub fn claimed_with_diagnostic_failure(action: CredentialOperationAction) -> ClaimFixture {
    let command = command(action);
    let (control, channel, ticket, written) = endpoint(&command, true);
    claimed_from_parts(control, channel, ticket, written, action)
}

fn claimed_from_parts(
    control: TestControl,
    channel: runne_provider::BrokerChannelBinding,
    ticket: PendingCredentialIssueTicketV1,
    written: Arc<Mutex<Vec<u8>>>,
    action: CredentialOperationAction,
) -> ClaimFixture {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let writer: Arc<dyn BrokeredProviderCredentialWriter> = Arc::new(FakeWriter {
        calls: calls.clone(),
        create_succeeds: false,
    });
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    let secret_input = if action == CredentialOperationAction::Pair {
        CredentialSecretInputPresence::Present
    } else {
        CredentialSecretInputPresence::Absent
    };
    ClaimFixture {
        claimed: claim_writer_authorization_with_legacy_parts(
            control,
            channel,
            ticket,
            &issuer,
            writer,
            secret_input,
        )
        .expect("claim"),
        calls,
        written,
    }
}

pub fn assert_frames(written: &Arc<Mutex<Vec<u8>>>, native_observed: bool) {
    let bytes = written.lock().expect("written").clone();
    let mut cursor = Cursor::new(bytes);
    assert!(matches!(
        CredentialBrokerFrameCodec::read_from(&mut cursor).expect("claim"),
        CredentialBrokerFrame::Claim { .. }
    ));
    let next = CredentialBrokerFrameCodec::read_from(&mut cursor).ok();
    if native_observed {
        assert!(matches!(
            next,
            Some(CredentialBrokerFrame::NativeEffectObserved {
                operation_id,
                binding,
            }) if operation_id == CredentialOperationId::from_bytes([21; 16]).expect("operation")
                && binding == CredentialBindingDigest::from_measured([13; 32]).expect("binding")
        ));
    } else {
        assert!(next.is_none());
    }
    let length: u64 = cursor.get_ref().len().try_into().unwrap();
    assert_eq!(cursor.position(), length);
}

fn endpoint(
    command: &CredentialBrokerCommand,
    fail_after_claim: bool,
) -> (
    TestControl,
    runne_provider::BrokerChannelBinding,
    PendingCredentialIssueTicketV1,
    Arc<Mutex<Vec<u8>>>,
) {
    let binding = CredentialBindingDigest::from_measured([13; 32]).expect("binding");
    let mut encoded_ticket = Vec::new();
    CredentialBrokerFrameCodec::write_to(
        &mut encoded_ticket,
        CredentialBrokerFrame::IssueTicket {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            ticket: RawCredentialTicket::generate().expect("ticket"),
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
    release::append_non_pair(&mut input, command);
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([11; 32]).unwrap();
    let written = Arc::new(Mutex::new(Vec::new()));
    let control = TestControl::new(input, written.clone(), fail_after_claim);
    (control, channel, ticket, written)
}
use super::legacy_cleanup_test_support as legacy;
pub fn command(action: CredentialOperationAction) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").expect("provider");
    let operation_id = CredentialOperationId::from_bytes([21; 16]).expect("operation");
    let version = CredentialVersionRef::new(provider.clone(), 1).expect("version");
    let (target, migration_binding) = match action {
        CredentialOperationAction::MigrateLegacy => {
            (CredentialBrokerTarget::LegacyImport(version), None)
        }
        CredentialOperationAction::LegacySourceCleanup => (legacy::target(version), None),
        CredentialOperationAction::WriterIdentityMigrationEffect => (
            CredentialBrokerTarget::Migration {
                migration_id: operation_id,
                phase: WriterIdentityMigrationPhase::OldWriterEffect,
            },
            Some(CredentialBindingDigest::from_measured([14; 32]).expect("migration")),
        ),
        CredentialOperationAction::WriterIdentityMigrationVerify => (
            CredentialBrokerTarget::Migration {
                migration_id: operation_id,
                phase: WriterIdentityMigrationPhase::NewWriterVerify,
            },
            Some(CredentialBindingDigest::from_measured([14; 32]).expect("migration")),
        ),
        _ => (CredentialBrokerTarget::Version(version), None),
    };
    CredentialBrokerCommand::new(
        operation_id,
        CredentialTicketAttempt::new(1).expect("attempt"),
        provider,
        action,
        target,
        CredentialLifecycleRevision::new(legacy::revision(action)).expect("revision"),
        CredentialFence::new(legacy::revision(action)).expect("fence"),
        migration_binding,
    )
    .expect("command")
}

struct FakeWriter {
    calls: Arc<Mutex<Vec<EffectCall>>>,
    create_succeeds: bool,
}

impl FakeWriter {
    fn record(&self, call: EffectCall) {
        self.calls.lock().expect("calls").push(call);
    }
}

impl BrokeredProviderCredentialWriter for FakeWriter {
    fn create_sealed_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredCreateInput,
        _pending: PendingCredentialSecretOpening,
        _envelope: SealedCredentialEnvelope,
    ) -> Result<(), SecureStoreError> {
        self.record(EffectCall::Create);
        self.create_succeeds
            .then_some(())
            .ok_or(SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn delete_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredDeleteInput,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        self.record(EffectCall::Delete);
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn import_legacy_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredMigrateLegacyInput,
    ) -> Result<(), SecureStoreError> {
        self.record(EffectCall::ImportLegacy);
        Ok(())
    }

    fn delete_legacy_source_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError> {
        self.record(EffectCall::DeleteLegacySource);
        Ok(())
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

struct TestControl {
    input: Cursor<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
    fail_after_claim: bool,
}

impl TestControl {
    fn new(input: Vec<u8>, written: Arc<Mutex<Vec<u8>>>, fail_after_claim: bool) -> Self {
        Self {
            input: Cursor::new(input),
            written,
            fail_after_claim,
        }
    }
}

impl Read for TestControl {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for TestControl {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut written = self.written.lock().expect("written");
        if self.fail_after_claim && !written.is_empty() {
            return Err(std::io::Error::other("diagnostic write denied"));
        }
        written.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
