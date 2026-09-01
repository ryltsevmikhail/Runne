#![cfg(target_os = "macos")]
#![allow(
    clippy::borrow_as_ptr,
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    reason = "test-only SCM_RIGHTS fixture mirrors the fixed native wire layout"
)]

#[path = "packaged_writer_observation_real_process/package.rs"]
mod package;
#[path = "packaged_writer_observation_real_process/protocol.rs"]
mod protocol;
#[path = "packaged_writer_observation_real_process/release.rs"]
mod release;

use std::io::Write as _;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use package::{PackageView, SigningMode, TestPackage};
use release::ReleaseFixture;
use runne_macos_process_identity::{
    MacOsPackagedWriterObservationError, MacOsProcessStartIdentity,
    MacOsUntrustedWriterEndpointHandoffV1,
};
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;

const ROLE_ENV: &str = "RUNNE_B2B3I_REAL_PROCESS_ROLE";
const WRITER_ENV: &str = "RUNNE_B2B3I_WRITER_PATH";
const SIGNING_IDENTITY_ENV: &str = "RUNNE_MACOS_SIGNING_IDENTITY";
const LOW_LEVEL_TEST: &str = "packaged_runned_creates_control_stream_and_writer_reaches_pending";
const AD_HOC_TEST: &str = "ad_hoc_package_reaches_release_match_and_signed_identity_rejects";
const DEVELOPER_ID_TEST: &str = "developer_id_package_reaches_one_provisional_writer_session";

#[test]
fn packaged_runned_creates_control_stream_and_writer_reaches_pending() {
    match std::env::var(ROLE_ENV).as_deref() {
        Ok("runne") => return low_level_writer_helper(),
        Ok("runned") => return low_level_daemon_helper(),
        _ => {}
    }
    let package = TestPackage::new(SigningMode::AdHoc);
    launch_daemon(&package, LOW_LEVEL_TEST);
}

#[test]
fn ad_hoc_package_reaches_release_match_and_signed_identity_rejects() {
    run_case(AD_HOC_TEST, SigningMode::AdHoc, ExpectedMatch::Rejected);
}

#[test]
#[ignore = "requires explicit RUNNE_MACOS_SIGNING_IDENTITY and an unlocked signing key"]
fn developer_id_package_reaches_one_provisional_writer_session() {
    let identity = std::env::var(SIGNING_IDENTITY_ENV)
        .expect("ignored qualification witness requires RUNNE_MACOS_SIGNING_IDENTITY");
    run_case(
        DEVELOPER_ID_TEST,
        SigningMode::DeveloperId(&identity),
        ExpectedMatch::Accepted,
    );
}

#[derive(Clone, Copy)]
enum ExpectedMatch {
    Accepted,
    Rejected,
}

fn run_case(test_name: &str, signing: SigningMode<'_>, expected: ExpectedMatch) {
    match std::env::var(ROLE_ENV).as_deref() {
        Ok("runne") => return writer_helper(expected),
        Ok("runned") => return daemon_helper(test_name),
        _ => {}
    }

    let package = TestPackage::new(signing);
    launch_daemon(&package, test_name);
}

fn launch_daemon(package: &TestPackage, test_name: &str) {
    let output = Command::new(package.view().daemon())
        .args(["--exact", test_name, "--nocapture"])
        .env(ROLE_ENV, "runned")
        .env(WRITER_ENV, package.view().writer())
        .output()
        .expect("launch packaged runned helper");
    assert_child_success("runned", &output);
}

fn low_level_writer_helper() {
    let handoff = MacOsUntrustedWriterEndpointHandoffV1::receive_from_stdin()
        .expect("receive exact writer handoff");
    handoff
        .observe_pending_packaged_writer()
        .expect("ad-hoc package still reaches low-level Pending");
}

fn low_level_daemon_helper() {
    let writer = std::env::var_os(WRITER_ENV).expect("writer path");
    let (ingress_sender, ingress_receiver) = UnixStream::pair().expect("ingress pair");
    let (daemon_control, writer_control) = UnixStream::pair().expect("control pair");
    let child = Command::new(writer)
        .args(["--exact", LOW_LEVEL_TEST, "--nocapture"])
        .env(ROLE_ENV, "runne")
        .stdin(Stdio::from(OwnedFd::from(ingress_receiver)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch packaged runne helper");
    let frame = protocol::handoff_frame([2; 32]);
    protocol::send_handoff(&ingress_sender, &writer_control, &frame);
    ingress_sender
        .shutdown(std::net::Shutdown::Write)
        .expect("finish ingress");
    drop(writer_control);
    let output = child.wait_with_output().expect("wait for packaged runne");
    drop(daemon_control);
    assert_child_success("runne", &output);
}

fn writer_helper(expected: ExpectedMatch) {
    let handoff = MacOsUntrustedWriterEndpointHandoffV1::receive_from_stdin()
        .expect("receive exact writer handoff");
    let transcript = handoff
        .observe_pending_writer_bootstrap()
        .expect("correct bootstrap prefix reaches retained native observation");
    let (pending_match, _pending_metadata) = transcript.into_release_verification();
    let release = ReleaseFixture::for_package(&PackageView::from_current_executable());
    let result = pending_match.test_only_match_verified_release(release.verified_exact());
    match expected {
        ExpectedMatch::Accepted => {
            result.expect("Developer-ID package must reach one provisional writer session");
        }
        ExpectedMatch::Rejected => assert_eq!(
            result.err(),
            Some(MacOsPackagedWriterObservationError::Rejected),
            "ad-hoc package must fail at exact signed code identity"
        ),
    }
}

fn daemon_helper(test_name: &str) {
    let package = PackageView::from_current_executable();
    let release = ReleaseFixture::for_package(&package);
    let signer = CredentialWriterSessionAttestationSigner::generate(protocol::CHANNEL)
        .expect("generate attestation signer");
    let handoff_frame = protocol::handoff_frame(signer.public_key());
    let writer = std::env::var_os(WRITER_ENV).expect("writer path");
    let (ingress_sender, ingress_receiver) = UnixStream::pair().expect("ingress pair");
    let (mut daemon_control, writer_control) = UnixStream::pair().expect("control pair");
    let child = Command::new(writer)
        .args(["--exact", test_name, "--nocapture"])
        .env(ROLE_ENV, "runne")
        .stdin(Stdio::from(OwnedFd::from(ingress_receiver)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch packaged runne helper");
    let writer_pid = NonZeroU32::new(child.id()).expect("writer pid");
    let writer_start = MacOsProcessStartIdentity::observe(writer_pid)
        .expect("observe writer process start")
        .digest();
    let daemon_start = MacOsProcessStartIdentity::observe(
        NonZeroU32::new(std::process::id()).expect("daemon pid"),
    )
    .expect("observe daemon process start")
    .digest();
    let prefix =
        protocol::bootstrap_prefix(&handoff_frame, signer, &release, writer_start, daemon_start);

    protocol::send_handoff(&ingress_sender, &writer_control, &handoff_frame);
    ingress_sender
        .shutdown(std::net::Shutdown::Write)
        .expect("finish ingress");
    drop(writer_control);
    daemon_control
        .write_all(&prefix)
        .expect("write exact bootstrap prefix");
    let output = child.wait_with_output().expect("wait for packaged runne");
    drop(daemon_control);
    assert_child_success("runne", &output);
}

fn assert_child_success(role: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{role} helper failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
