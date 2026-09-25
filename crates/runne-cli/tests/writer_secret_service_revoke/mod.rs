//! Production Linux writer Revoke evidence against one already-paired item.
use runne_api::ProviderCredentialRequestAuthorityPair;
use runne_platform_desktop::provider_credential_broker as platform;
use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
use runne_provider::{CredentialBrokerFrame as Frame, CredentialBrokerFrameCodec as Codec};
use runne_secure_store::{
    ExactAbsenceReadback, NativeProviderCredentialReaders, ProviderCredentialAccessPolicy,
};
use sha2::{Digest as _, Sha256};
use std::io::Write as _;
use std::os::unix::net::UnixStream;

use super::{native_support, support, writer_support};
#[path = "claims.rs"]
mod ticket;
use ticket::{claims, issue_ticket, revoke_command};

pub fn revoke_existing_item(binary: &std::path::Path, version: u64, service: &str) {
    assert!(
        !native_support::search_item(service).unwrap().is_empty(),
        "Pair must seed exact native item"
    );
    release_once(binary, version, service, false);
    assert!(
        !native_support::search_item(service).unwrap().is_empty(),
        "malformed Revoke release deleted item"
    );
    release_once(binary, version, service, true);
    assert!(
        native_support::search_item(service).unwrap().is_empty(),
        "accepted Revoke left exact native item"
    );
}

fn release_once(binary: &std::path::Path, version: u64, service: &str, accepted: bool) {
    let mut session = start_control_writer(binary);
    let command = send_revoke_claim(&mut session, version);
    send_release(&mut session.control, &command, accepted);
    let terminal_observed = read_terminal(&mut session.control, &command, accepted);
    drop(session.control);
    drop(session.child);
    native_support::clear_cache_item(service).unwrap();
    verify_revoke_readback(binary, service, command, accepted);
    assert_eq!(terminal_observed, accepted, "Revoke terminal release fence");
}

struct RevokeSession {
    control: UnixStream,
    child: native_support::Child,
    signer: Option<CredentialWriterSessionAttestationSigner>,
    start: [u8; 32],
    image: [u8; 32],
}

fn start_control_writer(binary: &std::path::Path) -> RevokeSession {
    let image: [u8; 32] = Sha256::digest(std::fs::read(binary).unwrap()).into();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(binary.to_owned(), image, support::RELEASE_TUPLE).unwrap(),
    );
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let startup_authority = support::fixture_authority(&issuer);
    let handoff_authority = support::fixture_authority(&issuer);
    let keys = runne_api::LaunchSecret::from_bytes(writer_support::LAUNCH_SECRET)
        .unwrap()
        .derive_keys();
    let authenticator =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let signer =
        CredentialWriterSessionAttestationSigner::generate(writer_support::CHANNEL).unwrap();
    let public_key = signer.public_key();
    let (control, endpoint) = UnixStream::pair().unwrap();
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
        writer_support::CHANNEL,
        public_key,
    )
    .unwrap();
    let transfer = std::thread::spawn(move || {
        platform::send_daemon_owned_writer_endpoint(
            sender,
            endpoint,
            &handoff_authority,
            writer_support::CHANNEL,
            public_key,
        )
    });
    let (startup, child_startup) = UnixStream::pair().unwrap();
    let child = platform::spawn_linux_writer_from_prepared_handoff(
        &spec,
        prepared,
        child_startup,
        &authenticator,
    )
    .unwrap();
    let child = native_support::Child(child);
    transfer.join().unwrap().unwrap();
    let start = child.0.writer_start_identity().unwrap();
    let _kill = platform::receive_linux_writer_startup(
        startup,
        startup_authority,
        &writer_support::LAUNCH_SECRET,
        support::RELEASE_TUPLE,
        writer_support::CHANNEL,
        public_key,
        platform::LinuxWriterLiveFacts {
            start_identity: start,
            image_digest: image,
        },
    )
    .unwrap();
    RevokeSession {
        control,
        child,
        signer: Some(signer),
        start,
        image,
    }
}

fn send_revoke_claim(
    session: &mut RevokeSession,
    version: u64,
) -> runne_provider::CredentialBrokerCommand {
    let command = revoke_command(version);
    let issue = issue_ticket(&command);
    let ticket = match Codec::read_from(&mut &issue[..]).unwrap() {
        Frame::IssueTicket { ticket, .. } => ticket.binding_digest(),
        _ => unreachable!(),
    };
    let claims = claims(&issue, session.start, session.image);
    let (attestation, _) = session.signer.take().unwrap().sign(claims).unwrap();
    session
        .control
        .write_all(&runne_provider::CredentialWriterSessionAttestationCodec::encode(&attestation))
        .unwrap();
    session.control.write_all(&issue).unwrap();
    match Codec::read_from(&mut session.control).unwrap() {
        Frame::Claim {
            operation_id,
            attempt,
            ticket: actual,
            binding,
            secret_offer: None,
        } => {
            assert_eq!(operation_id, command.operation_id());
            assert_eq!(attempt, command.ticket_attempt());
            assert_eq!(actual.binding_digest(), ticket);
            assert_eq!(
                binding,
                writer_support::digest(writer_support::SIGN_BINDING)
            );
        }
        _ => panic!("control-only Revoke claim expected"),
    }
    Codec::write_to(
        &mut session.control,
        Frame::ClaimAccepted {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
        },
    )
    .unwrap();
    command
}

fn send_release(
    control: &mut UnixStream,
    command: &runne_provider::CredentialBrokerCommand,
    accepted: bool,
) {
    Codec::write_to(
        control,
        Frame::NativeEffectRelease {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            binding: writer_support::digest(if accepted {
                writer_support::SIGN_BINDING
            } else {
                [0x98; 32]
            }),
        },
    )
    .unwrap();
}

fn read_terminal(
    control: &mut UnixStream,
    command: &runne_provider::CredentialBrokerCommand,
    accepted: bool,
) -> bool {
    if accepted {
        assert!(
            matches!(Codec::read_from(control).unwrap(), Frame::NativeEffectObserved { operation_id, binding } if operation_id == command.operation_id() && binding == writer_support::digest(writer_support::SIGN_BINDING)),
            "accepted Revoke terminal must match exact command"
        );
        true
    } else {
        matches!(
            Codec::read_from(control),
            Ok(Frame::NativeEffectObserved { .. })
        )
    }
}

fn verify_revoke_readback(
    binary: &std::path::Path,
    service: &str,
    command: runne_provider::CredentialBrokerCommand,
    accepted: bool,
) {
    let access =
        ProviderCredentialAccessPolicy::new(binary, &std::env::current_exe().unwrap()).unwrap();
    let (_, readback, _, _) = NativeProviderCredentialReaders::new(access).into_parts();
    let native_present = !native_support::search_item(service).unwrap().is_empty();
    assert_eq!(
        native_present, !accepted,
        "exact Secret Service item state after Revoke"
    );
    if accepted {
        let observed = readback
            .readback_exact_absence(ExactAbsenceReadback::new(command).unwrap())
            .unwrap_or_else(|error| {
                panic!("production exact-version absence readback failed: {error:?}")
            });
        assert!(
            !observed.present(),
            "independent exact-version readback after Revoke"
        );
    }
}
