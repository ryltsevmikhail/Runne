use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchSecret, ProviderCredentialBaseRequestAuthority,
    ProviderCredentialIntentConsumptionProof, ProviderCredentialRequestAuthorityIssuer,
    ProviderCredentialRequestAuthorityPair,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_platform_desktop::provider_credential_broker::send_test_daemon_owned_writer_evidence;
use runne_provider::{
    BeginCredentialOperation, BeginCredentialOperationOutcome, CredentialAuthorityPair,
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialOperationSnapshot, CredentialVersionRef, ProviderCredentialEnrollmentStore,
    ProviderId,
};

use super::*;

include!("pending_writer_test_support.rs");

struct BindingFixture {
    operation: CredentialOperationSnapshot,
    authority: ProviderCredentialBaseRequestAuthority,
    proof: ProviderCredentialIntentConsumptionProof,
    issuer: ProviderCredentialRequestAuthorityIssuer,
    release_tuple: [u8; 32],
}

fn binding_fixture(expires_at: i64) -> BindingFixture {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let qualified = measurements
        .issue_qualified_credential_release_tuple(
            measurements.release_manifest_digest([7; 32]).unwrap(),
        )
        .unwrap();
    let release_tuple = qualified.digest().as_bytes();
    let authority = issuer
        .issue_base([3; 32], release_tuple, [4; 32], 1, [6; 32], 1, [5; 32])
        .unwrap();
    let proof = issuer
        .issue_intent_proof([2; 32], [4; 32], [8; 32], [9; 32], expires_at)
        .unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment, _) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("pending-writer.sqlite"),
            lifecycle,
            enrollment,
        )
        .unwrap();
    let operation = match store
        .begin(
            BeginCredentialOperation::new(
                CommandId::from_bytes([1; 16]),
                IdempotencyKey::new("pending-writer").unwrap(),
                CredentialOperationId::from_bytes([1; 16]).unwrap(),
                CredentialInstallationOwnerId::from_bytes([3; 32]).unwrap(),
                provider.clone(),
                CredentialOperationAction::Pair,
                Some(CredentialVersionRef::new(provider, 1).unwrap()),
                None,
                CredentialLifecycleRevision::new(1).unwrap(),
                CredentialFence::new(1).unwrap(),
                runne_provider::CredentialBindingDigest::from_measured(*proof.proof_digest())
                    .unwrap(),
                u64::try_from(expires_at).unwrap(),
            )
            .unwrap()
            .with_qualified_release_tuple(qualified),
        )
        .unwrap()
    {
        BeginCredentialOperationOutcome::FreshWinner(operation) => operation,
        BeginCredentialOperationOutcome::ExactReplay(_) => panic!("fresh fixture"),
    };
    BindingFixture {
        operation,
        authority,
        proof,
        issuer,
        release_tuple,
    }
}

fn awaiting(
    fixture: &BindingFixture,
    channel: [u8; 32],
    transfer_authority: runne_api::ProviderCredentialBrokerTransferAuthority,
) -> (AwaitingVerifiedWriter, [u8; 32]) {
    let authority = DaemonBrokerAuthority::for_test(channel);
    let publication_key = authority.publication_public_key();
    let binding = PendingBrokerRendezvousBinding::new(
        &fixture.operation,
        &fixture.authority,
        &fixture.proof,
        100,
    )
    .unwrap();
    (
        AwaitingVerifiedWriter {
            binding,
            authority,
            transfer_authority,
        },
        publication_key,
    )
}

fn send_evidence(
    transport: std::os::unix::net::UnixStream,
    authenticator: &CredentialBrokerTransferAuthenticator,
    release_tuple: [u8; 32],
    channel: [u8; 32],
    publication_key: [u8; 32],
) -> Result<(), runne_platform_ports::provider_credential_broker::BrokerHandoffError> {
    send_test_daemon_owned_writer_evidence(
        transport,
        authenticator,
        [11; 32],
        [12; 32],
        release_tuple,
        channel,
        publication_key,
    )
}

#[test]
fn awaiting_writer_consumes_exact_session_and_release_evidence() {
    let fixture = binding_fixture(4_000_000_000);
    let (sealed, sender_authenticator) = transfer_authority(&fixture.issuer, [13; 32], [4; 32]);
    let channel = [14; 32];
    let (awaiting, publication_key) = awaiting(&fixture, channel, sealed);
    let release_tuple = fixture.release_tuple;
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let sender_thread = std::thread::spawn(move || {
        send_evidence(
            sender,
            &sender_authenticator,
            release_tuple,
            channel,
            publication_key,
        )
    });

    let admitted = awaiting
        .receive_writer_evidence(
            receiver,
            &fixture.operation,
            &fixture.authority,
            &fixture.proof,
            100,
        )
        .unwrap();
    sender_thread.join().unwrap().unwrap();
    let _ = admitted;
}

#[test]
fn awaiting_writer_rejects_unrelated_session_authenticator() {
    let fixture = binding_fixture(4_000_000_000);
    let (sealed, _) = transfer_authority(&fixture.issuer, [15; 32], [4; 32]);
    let (_, wrong) = transfer_authority(&fixture.issuer, [16; 32], [4; 32]);
    let channel = [17; 32];
    let (awaiting, publication_key) = awaiting(&fixture, channel, sealed);
    let release_tuple = fixture.release_tuple;
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let sender_thread = std::thread::spawn(move || {
        send_evidence(sender, &wrong, release_tuple, channel, publication_key)
    });

    assert!(
        awaiting
            .receive_writer_evidence(
                receiver,
                &fixture.operation,
                &fixture.authority,
                &fixture.proof,
                100,
            )
            .is_err()
    );
    assert!(sender_thread.join().unwrap().is_err());
}

#[test]
fn awaiting_writer_rejects_expiry_and_full_binding_changes() {
    for changed in [
        "expired",
        "session",
        "release",
        "peer",
        "daemon",
        "database",
        "supervisor",
    ] {
        let fixture = binding_fixture(4_000_000_000);
        let (sealed, sender_authenticator) = transfer_authority(&fixture.issuer, [18; 32], [4; 32]);
        let channel = [19; 32];
        let (awaiting, publication_key) = awaiting(&fixture, channel, sealed);
        let release_tuple = fixture.release_tuple;
        let candidate = match changed {
            "session" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [20; 32],
                1,
                [6; 32],
                1,
                [5; 32],
            ),
            "release" => fixture
                .issuer
                .issue_base([3; 32], [21; 32], [4; 32], 1, [6; 32], 1, [5; 32]),
            "peer" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                1,
                [6; 32],
                1,
                [22; 32],
            ),
            "daemon" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                1,
                [23; 32],
                1,
                [5; 32],
            ),
            "database" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                1,
                [6; 32],
                2,
                [5; 32],
            ),
            "supervisor" => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                2,
                [6; 32],
                1,
                [5; 32],
            ),
            _ => fixture.issuer.issue_base(
                [3; 32],
                fixture.release_tuple,
                [4; 32],
                1,
                [6; 32],
                1,
                [5; 32],
            ),
        }
        .unwrap();
        let now = if changed == "expired" {
            4_000_000_000
        } else {
            100
        };
        let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        let sender_thread = std::thread::spawn(move || {
            send_evidence(
                sender,
                &sender_authenticator,
                release_tuple,
                channel,
                publication_key,
            )
        });

        assert!(
            awaiting
                .receive_writer_evidence(
                    receiver,
                    &fixture.operation,
                    &candidate,
                    &fixture.proof,
                    now,
                )
                .is_err()
        );
        assert!(sender_thread.join().unwrap().is_err());
    }
}
