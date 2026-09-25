//! Opt-in production CLI writer cycle against the owner Linux Secret Service.
#![cfg(target_os = "linux")]

#[path = "writer_secret_service_support/mod.rs"]
mod native_support;
#[path = "writer_secret_service_revoke/mod.rs"]
mod revoke_support;
#[path = "linux_writer_handshake_support/mod.rs"]
#[allow(dead_code)]
mod support;
#[path = "writer_fixture_support/mod.rs"]
mod writer_support;

use runne_api::ProviderCredentialRequestAuthorityPair;
use runne_platform_desktop::provider_credential_broker as platform;
use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
use runne_provider::{CredentialBrokerFrame as Frame, CredentialBrokerFrameCodec as Codec};
use runne_secure_store::{
    ExactVersionReadback, NativeProviderCredentialReaders, ProviderCredentialAccessPolicy,
};
use sha2::{Digest as _, Sha256};
use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
#[ignore = "opt-in owner-session native Secret Service E2E; run under a valid keyutils session keyring"]
fn production_writer_pair_and_revoke_are_read_back_and_bad_release_is_fenced() {
    assert!(std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some());
    assert_eq!(
        std::env::var_os("RUNNE_NATIVE_SECRET_SERVICE_E2E").as_deref(),
        Some(std::ffi::OsStr::new("1"))
    );
    assert!(
        Command::new("keyctl")
            .args(["show", "@s"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let binary = std::path::PathBuf::from(env!("CARGO_BIN_EXE_runne"));
    let base = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    for (offset, accepted) in [(0, true), (1, false)] {
        run_pair(&binary, base.saturating_add(offset), accepted);
    }
}

fn run_pair(binary: &std::path::Path, version: u64, accepted: bool) {
    let (cleanup, service) = native_support::ExactItemCleanup::for_version(version);
    let _cleanup = cleanup;
    native_support::clear_item(&service).unwrap();
    native_support::clear_cache_item(&service).unwrap();
    let mut session = start_pair_writer(binary);
    let command = send_pair(&mut session, version, accepted);
    let native_service_entry_present = !native_support::search_item(&service).unwrap().is_empty();
    let access =
        ProviderCredentialAccessPolicy::new(binary, &std::env::current_exe().unwrap()).unwrap();
    let (_, readback, _, _) = NativeProviderCredentialReaders::new(access).into_parts();
    let observed = readback.readback_exact_version(ExactVersionReadback::new(command).unwrap());
    drop(session);
    let observed = observed
        .unwrap_or_else(|error| panic!("production exact-version readback failed: {error:?}"));
    assert_eq!(
        native_service_entry_present, accepted,
        "exact Secret Service item state"
    );
    assert_eq!(
        observed.present(),
        accepted,
        "exact native Secret Service readback"
    );
    if accepted {
        revoke_support::revoke_existing_item(binary, version, &service);
    }
    native_support::clear_item(&service).unwrap();
    native_support::clear_cache_item(&service).unwrap();
}

struct PairSession {
    control: UnixStream,
    relay: Option<platform::LinuxAuthenticatedPairSecretRelay>,
    _child: native_support::Child,
    signer: Option<CredentialWriterSessionAttestationSigner>,
    start: [u8; 32],
    image: [u8; 32],
}

fn start_pair_writer(binary: &std::path::Path) -> PairSession {
    let image: [u8; 32] = Sha256::digest(std::fs::read(binary).unwrap()).into();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(binary.to_owned(), image, support::RELEASE_TUPLE).unwrap(),
    );
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let startup_authority = support::fixture_authority(&issuer);
    let handoff_authority = support::fixture_authority(&issuer);
    let keys = runne_api::LaunchSecret::from_bytes(support::LAUNCH_SECRET)
        .unwrap()
        .derive_keys();
    let authenticator =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let signer = CredentialWriterSessionAttestationSigner::generate(support::CHANNEL).unwrap();
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
        support::CHANNEL,
        public_key,
    )
    .unwrap();
    let transfer = std::thread::spawn(move || {
        platform::send_daemon_owned_writer_endpoint(
            sender,
            endpoint,
            &handoff_authority,
            support::CHANNEL,
            public_key,
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
    let child = native_support::Child(child);
    transfer.join().unwrap().unwrap();
    let start = child.0.writer_start_identity().unwrap();
    let _kill = platform::receive_linux_writer_startup(
        startup,
        startup_authority,
        &support::LAUNCH_SECRET,
        support::RELEASE_TUPLE,
        support::CHANNEL,
        public_key,
        platform::LinuxWriterLiveFacts {
            start_identity: start,
            image_digest: image,
        },
    )
    .unwrap();
    PairSession {
        control,
        relay: Some(relay),
        _child: child,
        signer: Some(signer),
        start,
        image,
    }
}

fn send_pair(
    session: &mut PairSession,
    version: u64,
    accepted: bool,
) -> runne_provider::CredentialBrokerCommand {
    let (claims, issue) = writer_support::issue_claims_at_version(
        session.start,
        session.image,
        support::RELEASE_TUPLE,
        version,
    );
    let (attestation, publication) = session.signer.take().unwrap().sign(claims).unwrap();
    session
        .control
        .write_all(&runne_provider::CredentialWriterSessionAttestationCodec::encode(&attestation))
        .unwrap();
    session.control.write_all(&issue).unwrap();
    let command = writer_support::pair_command_at_version(version);
    let expected_ticket = match Codec::read_from(&mut &issue[..]).unwrap() {
        Frame::IssueTicket { ticket, .. } => ticket.binding_digest(),
        _ => unreachable!(),
    };
    let offer = expect_claim(&mut session.control, &command, expected_ticket);
    Codec::write_to(
        &mut session.control,
        Frame::ClaimAccepted {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
        },
    )
    .unwrap();
    let offer_copy = runne_provider::CredentialSecretOfferCodec::decode(
        &runne_provider::CredentialSecretOfferCodec::encode(&offer),
    )
    .unwrap();
    let published = publication
        .sign(offer_copy, writer_support::digest(support::CHANNEL))
        .unwrap();
    let relay_frame = runne_provider::CredentialSecretRelayFrameCodec::encode(&offer, &published);
    let disposable = format!("runne-e2e-disposable-credential-{version}").into_bytes();
    session
        .relay
        .take()
        .unwrap()
        .seal_and_write(&relay_frame, zeroize::Zeroizing::new(disposable))
        .unwrap();
    Codec::write_to(
        &mut session.control,
        Frame::NativeEffectRelease {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            binding: writer_support::digest(if accepted {
                writer_support::SIGN_BINDING
            } else {
                [0x99; 32]
            }),
        },
    )
    .unwrap();
    if accepted {
        assert!(
            matches!(Codec::read_from(&mut session.control).unwrap(), Frame::NativeEffectObserved {
            operation_id, binding,
        } if operation_id == command.operation_id() && binding == writer_support::digest(writer_support::SIGN_BINDING))
        );
    } else {
        assert!(
            Codec::read_from(&mut session.control).is_err(),
            "rejected release must not report an effect"
        );
    }
    command
}

fn expect_claim(
    control: &mut UnixStream,
    command: &runne_provider::CredentialBrokerCommand,
    ticket: runne_provider::CredentialBindingDigest,
) -> runne_provider::CredentialSecretClaimOffer {
    match Codec::read_from(control).unwrap() {
        Frame::Claim {
            operation_id,
            attempt,
            ticket: actual,
            binding,
            secret_offer: Some(offer),
        } => {
            assert_eq!(operation_id, command.operation_id());
            assert_eq!(attempt, command.ticket_attempt());
            assert_eq!(actual.binding_digest(), ticket);
            assert_eq!(
                binding,
                writer_support::digest(writer_support::SIGN_BINDING)
            );
            offer
        }
        _ => panic!("exact Pair claim expected"),
    }
}
