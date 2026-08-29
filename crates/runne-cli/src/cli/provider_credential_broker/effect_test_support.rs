use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};

use runne_provider::{
    ClaimedWriterAuthorization, CredentialBindingDigest, CredentialBrokerCommand,
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialBrokerTarget,
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialTicketAttempt,
    CredentialVersionRef, CredentialWriterAuthorityPair, NativeCredentialDeletionProof, ProviderId,
    RawCredentialTicket, WriterIdentityMigrationPhase,
};
use runne_secure_store::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredProviderCredentialWriter,
    BrokeredWriterIdentityMigrationInput, BrokeredWriterIdentityVerificationInput,
    ProviderCredentialMaterial, SecureStoreError, WriterIdentityMigrationObservation,
};

use super::claim::{
    AuthenticatedDaemonControlEndpoint, ClaimedWriterControl, claim_writer_authorization_for_test,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectCall {
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
    let (endpoint, written) = endpoint(&command, false);
    claimed_from_endpoint(endpoint, written)
}

pub fn claimed_with_diagnostic_failure(action: CredentialOperationAction) -> ClaimFixture {
    let command = command(action);
    let (endpoint, written) = endpoint(&command, true);
    claimed_from_endpoint(endpoint, written)
}

fn claimed_from_endpoint(
    endpoint: AuthenticatedDaemonControlEndpoint,
    written: Arc<Mutex<Vec<u8>>>,
) -> ClaimFixture {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let writer: Arc<dyn BrokeredProviderCredentialWriter> = Arc::new(FakeWriter {
        calls: calls.clone(),
    });
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    ClaimFixture {
        claimed: claim_writer_authorization_for_test(endpoint, &issuer, writer).expect("claim"),
        calls,
        written,
    }
}

pub fn pair_claimed() -> ClaimFixture {
    claimed(CredentialOperationAction::Pair)
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
    assert_eq!(cursor.position(), u64::try_from(cursor.get_ref().len()).expect("length"));
}

fn endpoint(
    command: &CredentialBrokerCommand,
    fail_after_claim: bool,
) -> (AuthenticatedDaemonControlEndpoint, Arc<Mutex<Vec<u8>>>) {
    let binding = CredentialBindingDigest::from_measured([13; 32]).expect("binding");
    let mut input = Vec::new();
    CredentialBrokerFrameCodec::write_to(
        &mut input,
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
    CredentialBrokerFrameCodec::write_to(
        &mut input,
        CredentialBrokerFrame::ClaimAccepted {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
        },
    )
    .expect("ack");
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([11; 32]).expect("channel");
    let written = Arc::new(Mutex::new(Vec::new()));
    (
        AuthenticatedDaemonControlEndpoint::for_test(
            TestControl::new(input, written.clone(), fail_after_claim),
            [11; 32],
            channel,
        ),
        written,
    )
}

fn command(action: CredentialOperationAction) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").expect("provider");
    let operation_id = CredentialOperationId::from_bytes([21; 16]).expect("operation");
    let version = CredentialVersionRef::new(provider.clone(), 1).expect("version");
    let (target, migration_binding) = match action {
        CredentialOperationAction::MigrateLegacy => {
            (CredentialBrokerTarget::LegacyImport(version), None)
        }
        CredentialOperationAction::LegacySourceCleanup => (CredentialBrokerTarget::LegacySource, None),
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
        CredentialLifecycleRevision::new(1).expect("revision"),
        CredentialFence::new(1).expect("fence"),
        migration_binding,
    )
    .expect("command")
}

struct FakeWriter {
    calls: Arc<Mutex<Vec<EffectCall>>>,
}

impl FakeWriter {
    fn record(&self, call: EffectCall) {
        self.calls.lock().expect("calls").push(call);
    }
}

impl BrokeredProviderCredentialWriter for FakeWriter {
    fn create_exact(
        &self,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredCreateInput,
        _material: &ProviderCredentialMaterial,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
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
