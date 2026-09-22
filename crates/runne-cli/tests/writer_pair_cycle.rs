//! Real Linux child, production claim/effect and sealer; fake in-memory store.
#![cfg(target_os = "linux")]
use runne_platform_desktop::provider_credential_broker::{
    self as platform, LinuxWriterLiveFacts, RetainedWriterProcess as _, UnixRetainedWriterProcess,
};
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
use runne_provider::{CredentialBrokerFrame as Frame, CredentialBrokerFrameCodec as Codec};
use sha2::Digest as _;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
#[path = "writer_fixture_support/mod.rs"]
mod support;
use support::*;

struct Child(UnixRetainedWriterProcess);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.terminate_retained_child();
        let _ = self.0.reap_retained_child();
    }
}

#[test]
#[ignore = "requires the owner Linux session-bus socket; store and credential are fake"]
fn linux_pair_process_claims_writes_and_reads_back() {
    pair_cycle(true);
}

#[test]
#[ignore = "requires the owner Linux session-bus socket; store and credential are fake"]
fn linux_pair_wrong_effect_release_leaves_version_absent() {
    pair_cycle(false);
}

fn pair_cycle(release_valid: bool) {
    let built = std::process::Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "-p",
            "runne-cli",
            "--example",
            "writer_cycle_fixture",
        ])
        .output()
        .unwrap();
    assert!(built.status.success(), "cycle example build failed");
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_runne"))
        .parent()
        .unwrap()
        .join("examples/writer_cycle_fixture");
    let image: [u8; 32] = sha2::Sha256::digest(std::fs::read(&binary).unwrap()).into();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(binary, image, RELEASE_TUPLE).unwrap(),
    );
    let (issuer, _) = runne_api::ProviderCredentialRequestAuthorityPair::new().split();
    let transfer_authority = fixture_authority(&issuer);
    let startup_authority = fixture_authority(&issuer);
    let keys = runne_api::LaunchSecret::from_bytes(LAUNCH_SECRET)
        .unwrap()
        .derive_keys();
    let authenticator =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL).unwrap();
    let key = signer.public_key();
    let (mut control, endpoint) = UnixStream::pair().unwrap();
    control
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    control
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let prepared = platform::prepare_daemon_owned_writer_endpoint_handoff(
        receiver,
        &authenticator,
        CHANNEL,
        key,
    )
    .unwrap();
    let transfer = std::thread::spawn(move || {
        platform::send_daemon_owned_writer_endpoint(
            sender,
            endpoint,
            &transfer_authority,
            CHANNEL,
            key,
        )
    });
    let (startup, child_startup) = UnixStream::pair().unwrap();
    let (child, relay) = platform::spawn_linux_pair_writer_from_prepared_handoff(
        &spec,
        prepared,
        child_startup,
        &authenticator,
    )
    .unwrap();
    let child = Child(child);
    transfer.join().unwrap().unwrap();
    let start = child.0.writer_start_identity().unwrap();
    let _kill = platform::receive_linux_writer_startup(
        startup,
        startup_authority,
        &LAUNCH_SECRET,
        RELEASE_TUPLE,
        CHANNEL,
        key,
        LinuxWriterLiveFacts {
            start_identity: start,
            image_digest: image,
        },
    )
    .unwrap();
    let (claims, issue) = issue_claims(start, image, RELEASE_TUPLE);
    let (attestation, publication_signer) = signer.sign(claims).unwrap();
    let expected_ticket = match Codec::read_from(&mut issue.as_slice()).unwrap() {
        Frame::IssueTicket { ticket, .. } => ticket.binding_digest(),
        _ => unreachable!(),
    };
    control
        .write_all(&runne_provider::CredentialWriterSessionAttestationCodec::encode(&attestation))
        .unwrap();
    control.write_all(&issue).unwrap();
    let command = pair_command();
    let offer = expect_exact_pair_claim(&mut control, &command, expected_ticket);
    Codec::write_to(
        &mut control,
        Frame::ClaimAccepted {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
        },
    )
    .unwrap();
    relay_publication(relay, &offer, publication_signer);
    finish_release_phase(&mut control, &command, release_valid);
}

fn relay_publication(
    relay: platform::LinuxAuthenticatedPairSecretRelay,
    offer: &runne_provider::CredentialSecretClaimOffer,
    publication_signer: runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner,
) {
    let offer_copy = runne_provider::CredentialSecretOfferCodec::decode(
        &runne_provider::CredentialSecretOfferCodec::encode(offer),
    )
    .unwrap();
    let publication = publication_signer
        .sign(offer_copy, digest(CHANNEL))
        .unwrap();
    let relay_frame = runne_provider::CredentialSecretRelayFrameCodec::encode(offer, &publication);
    relay
        .seal_and_write(
            &relay_frame,
            zeroize::Zeroizing::new(b"fixture-only-key".to_vec()),
        )
        .unwrap();
}

fn expect_exact_pair_claim(
    control: &mut UnixStream,
    command: &runne_provider::CredentialBrokerCommand,
    expected_ticket: runne_provider::CredentialBindingDigest,
) -> runne_provider::CredentialSecretClaimOffer {
    match Codec::read_from(control).unwrap() {
        Frame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer: Some(offer),
        } => {
            assert_eq!(operation_id, command.operation_id());
            assert_eq!(attempt, command.ticket_attempt());
            assert_eq!(binding, digest(SIGN_BINDING));
            assert_eq!(ticket.binding_digest(), expected_ticket);
            offer
        }
        _ => panic!("exact Pair claim with an ephemeral offer required"),
    }
}

fn finish_release_phase(
    control: &mut UnixStream,
    command: &runne_provider::CredentialBrokerCommand,
    release_valid: bool,
) {
    Codec::write_to(
        control,
        Frame::NativeEffectRelease {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            binding: digest(if release_valid {
                SIGN_BINDING
            } else {
                [99; 32]
            }),
        },
    )
    .unwrap();
    if release_valid {
        assert!(
            matches!(Codec::read_from(control).unwrap(), Frame::NativeEffectObserved {
        operation_id, binding,
    } if operation_id == command.operation_id() && binding == digest(SIGN_BINDING))
        );
    }
    let mut readback = [0; 8];
    control
        .read_exact(&mut readback)
        .expect("child completed native-reader metadata readback");
    assert_eq!(
        &readback,
        if release_valid {
            b"readback"
        } else {
            b"noeffect"
        }
    );
}
