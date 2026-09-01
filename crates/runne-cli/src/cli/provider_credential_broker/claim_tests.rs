use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};

use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialEnrollmentAuthorityPair,
    CredentialFence, CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialSecretInputPresence, CredentialTicketAttempt, CredentialVersionRef, ProviderId,
    RawCredentialTicket,
};
use runne_secure_store::{NativeProviderCredentialWriters, ProviderCredentialAccessPolicy};

use super::claim::{
    AuthenticatedDaemonControlEndpoint, claim_writer_authorization_for_test,
};
#[cfg(target_os = "macos")]
use super::claim::claim_writer_authorization;

#[path = "claim_tests/presence.rs"]
mod presence;

#[test]
#[cfg(target_os = "macos")]
fn production_claim_accepts_only_the_native_authenticated_bundle() {
    let claim: fn(
        NativeProviderCredentialWriters,
        CredentialSecretInputPresence,
    ) -> Result<super::claim::ClaimedWriterControl, super::CliError> =
        claim_writer_authorization;
    let _ = claim;
}

#[test]
fn claim_runner_rejects_wrong_first_frame_without_writing_a_claim() {
    let command = command(1, CredentialOperationAction::Pair);
    let (endpoint, written) = endpoint(
        CredentialBrokerFrame::ClaimAccepted {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
        },
        None,
    );

    assert!(claim_for_test(endpoint, CredentialSecretInputPresence::Present).is_err());
    assert!(written.lock().expect("written").is_empty());
}

#[test]
fn claim_runner_rejects_substituted_channel_without_writing_a_claim() {
    let command = command(2, CredentialOperationAction::Pair);
    let (endpoint, written) = endpoint(issue(command, binding(), [12; 32]), None);
    assert!(claim_for_test(endpoint, CredentialSecretInputPresence::Present).is_err());
    assert!(written.lock().expect("written").is_empty());
}

#[test]
fn claim_runner_rejects_internally_mismatched_channel_authority() {
    let command = command(8, CredentialOperationAction::Pair);
    let (endpoint, written) =
        endpoint_with_channel(issue(command, binding(), [11; 32]), None, [12; 32]);

    assert!(claim_for_test(endpoint, CredentialSecretInputPresence::Present).is_err());
    assert!(written.lock().expect("written").is_empty());
}

#[test]
fn claim_runner_rejects_denied_or_mismatched_ack_after_one_claim() {
    let command = command(4, CredentialOperationAction::Pair);
    for ack in [
        CredentialBrokerFrame::ClaimDenied {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            disposition: runne_provider::CredentialDisposition::AccessDenied,
        },
        CredentialBrokerFrame::ClaimAccepted {
            operation_id: command_with_attempt_and_action(5, 1, CredentialOperationAction::Pair)
                .operation_id(),
            attempt: command.ticket_attempt(),
        },
    ] {
        let (endpoint, written) = endpoint(issue(command.clone(), binding(), [11; 32]), Some(ack));
        assert!(claim_for_test(endpoint, CredentialSecretInputPresence::Present).is_err());
        assert_one_claim(&written, true);
    }
}

#[test]
fn pair_claim_sends_one_ticket_and_returns_post_ack_authorization() {
    let command = command(6, CredentialOperationAction::Pair);
    let (endpoint, written) = endpoint(
        issue(command.clone(), binding(), [11; 32]),
        Some(accepted(&command)),
    );

    let claimed = claim_for_test(endpoint, CredentialSecretInputPresence::Present)
        .expect("exact acknowledgement");
    assert_eq!(Arc::strong_count(&written), 2, "control remains retained");
    drop(claimed);
    assert_eq!(
        Arc::strong_count(&written),
        1,
        "control closes with authority"
    );
    assert_one_claim(&written, true);
}

#[test]
fn non_pair_claim_never_creates_a_secret_offer_or_pending_opening() {
    let command = command(7, CredentialOperationAction::Revoke);
    let (endpoint, written) = endpoint(
        issue(command.clone(), binding(), [11; 32]),
        Some(accepted(&command)),
    );

    let claimed = claim_for_test(endpoint, CredentialSecretInputPresence::Absent)
        .expect("exact acknowledgement");
    let authorized = claimed.authorize_without_secret().expect("non-pair effect");
    assert_eq!(authorized.command_for_test(), &command);
    assert_eq!(Arc::strong_count(&written), 2, "control remains retained");
    drop(authorized);
    assert_eq!(
        Arc::strong_count(&written),
        1,
        "control closes with authority"
    );
    assert_one_claim(&written, false);
}

#[test]
fn secret_path_is_pair_only_and_consumes_the_post_ack_state() {
    let pair = command(9, CredentialOperationAction::Pair);
    let (pair_endpoint, _) = endpoint(
        issue(pair.clone(), binding(), [11; 32]),
        Some(accepted(&pair)),
    );
    let claimed = claim_for_test(pair_endpoint, CredentialSecretInputPresence::Present)
        .expect("pair acknowledgement");
    assert!(claimed.authorize_without_secret().is_err());

    let revoke = command(10, CredentialOperationAction::Revoke);
    let (revoke_endpoint, _) = endpoint(
        issue(revoke.clone(), binding(), [11; 32]),
        Some(accepted(&revoke)),
    );
    let claimed = claim_for_test(revoke_endpoint, CredentialSecretInputPresence::Absent)
        .expect("revoke acknowledgement");
    assert!(claimed.read_pair_secret(&mut PanicReader).is_err());
}

fn endpoint(
    issue: CredentialBrokerFrame,
    ack: Option<CredentialBrokerFrame>,
) -> (AuthenticatedDaemonControlEndpoint, Arc<Mutex<Vec<u8>>>) {
    endpoint_with_channel(issue, ack, [11; 32])
}

fn claim_for_test(
    endpoint: AuthenticatedDaemonControlEndpoint,
    secret_input: CredentialSecretInputPresence,
) -> Result<super::claim::ClaimedWriterControl, super::CliError> {
    let writers = native_writers();
    let (issuer, writer) = writers.into_parts();
    claim_writer_authorization_for_test(endpoint, &issuer, writer, secret_input)
}

fn endpoint_with_channel(
    issue: CredentialBrokerFrame,
    ack: Option<CredentialBrokerFrame>,
    measured_channel: [u8; 32],
) -> (AuthenticatedDaemonControlEndpoint, Arc<Mutex<Vec<u8>>>) {
    let mut incoming = Vec::new();
    CredentialBrokerFrameCodec::write_to(&mut incoming, issue).expect("issue frame");
    if let Some(ack) = ack {
        CredentialBrokerFrameCodec::write_to(&mut incoming, ack).expect("ack frame");
    }
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements
        .broker_channel_binding(measured_channel)
        .expect("channel binding");
    let written = Arc::new(Mutex::new(Vec::new()));
    (
        AuthenticatedDaemonControlEndpoint::for_test(
            TestControl::new(incoming, written.clone()),
            [11; 32],
            channel,
        ),
        written,
    )
}

fn issue(
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel_binding: [u8; 32],
) -> CredentialBrokerFrame {
    CredentialBrokerFrame::IssueTicket {
        operation_id: command.operation_id(),
        attempt: command.ticket_attempt(),
        ticket: RawCredentialTicket::generate().expect("ticket"),
        channel_binding,
        binding,
        command,
    }
}

fn accepted(command: &CredentialBrokerCommand) -> CredentialBrokerFrame {
    CredentialBrokerFrame::ClaimAccepted {
        operation_id: command.operation_id(),
        attempt: command.ticket_attempt(),
    }
}

fn assert_one_claim(written: &Arc<Mutex<Vec<u8>>>, expects_secret_offer: bool) {
    let bytes = written.lock().expect("written").clone();
    let mut cursor = Cursor::new(bytes);
    let frame = CredentialBrokerFrameCodec::read_from(&mut cursor).expect("claim frame");
    assert_eq!(
        cursor.position(),
        u64::try_from(cursor.get_ref().len()).expect("test frame length")
    );
    assert!(matches!(
        frame,
        CredentialBrokerFrame::Claim { secret_offer, .. }
            if secret_offer.is_some() == expects_secret_offer
    ));
}

fn command(id: u8, action: CredentialOperationAction) -> CredentialBrokerCommand {
    command_with_attempt_and_action(id, 1, action)
}

fn command_with_attempt_and_action(
    id: u8,
    attempt: u64,
    action: CredentialOperationAction,
) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").expect("provider");
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([id; 16]).expect("operation"),
        CredentialTicketAttempt::new(attempt).expect("attempt"),
        provider.clone(),
        action,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).expect("version")),
        CredentialLifecycleRevision::new(1).expect("revision"),
        CredentialFence::new(1).expect("fence"),
        None,
    )
    .expect("command")
}

fn binding() -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([13; 32]).expect("binding")
}

fn native_writers() -> NativeProviderCredentialWriters {
    let executable = std::env::current_exe().expect("test executable");
    let access = ProviderCredentialAccessPolicy::new(&executable, &executable)
        .expect("measured writer policy");
    NativeProviderCredentialWriters::new_for_test(access)
}

struct TestControl {
    input: Cursor<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl TestControl {
    fn new(input: Vec<u8>, written: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            input: Cursor::new(input),
            written,
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
        self.written.lock().expect("written").write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct PanicReader;

impl Read for PanicReader {
    fn read(&mut self, _bytes: &mut [u8]) -> std::io::Result<usize> {
        panic!("non-Pair path must not read a secret source")
    }
}
