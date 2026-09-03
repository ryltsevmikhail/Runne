#![cfg(test)]
#![allow(unsafe_code)]
#![allow(
    clippy::borrow_as_ptr,
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    reason = "shared test-only SCM_RIGHTS fixture mirrors the fixed native wire layout"
)]

#[allow(
    dead_code,
    reason = "shared helper retains the opt-in Developer-ID path"
)]
#[path = "../tests/packaged_writer_observation_real_process/package.rs"]
mod package;
#[path = "../tests/packaged_writer_observation_real_process/protocol.rs"]
mod protocol;
#[allow(
    dead_code,
    reason = "shared helper retains exact-release qualification"
)]
#[path = "../tests/packaged_writer_observation_real_process/release.rs"]
mod release;

use std::io::Write as _;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use package::{PackageView, SigningMode, TestPackage};
use release::ReleaseFixture;
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;

use crate::packaged_writer_observation::FinalRaceDrift;
use crate::{
    MacOsPackagedWriterObservationError, MacOsProcessStartIdentity,
    MacOsUntrustedWriterEndpointHandoffV1,
};

const ROLE_ENV: &str = "RUNNE_B2B3I_FINAL_RACE_ROLE";
const WRITER_ENV: &str = "RUNNE_B2B3I_FINAL_RACE_WRITER";
const RACE_ENV: &str = "RUNNE_B2B3I_FINAL_RACE_KIND";
const TEST_NAME: &str = "provisional_writer_session_tests::final_native_races_are_rejected";

#[test]
fn final_native_races_are_rejected() {
    match std::env::var(ROLE_ENV).as_deref() {
        Ok("writer") => return writer_helper(),
        Ok("daemon") => return daemon_helper(),
        _ => {}
    }

    for race in ["package", "peer", "process", "seccode"] {
        let package = TestPackage::new(SigningMode::AdHoc);
        let output = Command::new(package.view().daemon())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST", "1")
            .env(ROLE_ENV, "daemon")
            .env(RACE_ENV, race)
            .env(WRITER_ENV, package.view().writer())
            .output()
            .expect("launch packaged daemon race helper");
        assert_child_success(race, &output);
    }
}

fn writer_helper() {
    let handoff = MacOsUntrustedWriterEndpointHandoffV1::receive_from_stdin()
        .expect("receive exact writer handoff");
    let transcript = handoff
        .test_only_observe_pending_writer_bootstrap(Duration::from_secs(10))
        .expect("bootstrap reaches retained native observation");
    let (pending, _metadata) = transcript.into_release_verification();
    let race = match std::env::var(RACE_ENV).as_deref() {
        Ok("package") => FinalRaceDrift::Package,
        Ok("peer") => FinalRaceDrift::Peer,
        Ok("process") => FinalRaceDrift::Process,
        Ok("seccode") => FinalRaceDrift::SecCode,
        _ => panic!("unknown final race"),
    };
    assert_eq!(
        pending.test_only_revalidate_after_final_race(race).err(),
        Some(MacOsPackagedWriterObservationError::Rejected)
    );
}

fn daemon_helper() {
    let package = PackageView::from_current_executable();
    let release = ReleaseFixture::for_package(&package);
    let signer = CredentialWriterSessionAttestationSigner::generate(protocol::CHANNEL)
        .expect("generate attestation signer");
    let handoff_frame = protocol::handoff_frame(signer.public_key());
    let writer = std::env::var_os(WRITER_ENV).expect("writer path");
    let (ingress_sender, ingress_receiver) = UnixStream::pair().expect("ingress pair");
    let (mut daemon_control, writer_control) = UnixStream::pair().expect("control pair");
    let child = Command::new(writer)
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(ROLE_ENV, "writer")
        .env(RACE_ENV, std::env::var(RACE_ENV).expect("race kind"))
        .stdin(Stdio::from(OwnedFd::from(ingress_receiver)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch packaged writer race helper");
    let writer_pid = NonZeroU32::new(child.id()).expect("writer pid");
    let writer_start = MacOsProcessStartIdentity::observe(writer_pid)
        .expect("observe writer start")
        .digest();
    let daemon_start = MacOsProcessStartIdentity::observe(
        NonZeroU32::new(std::process::id()).expect("daemon pid"),
    )
    .expect("observe daemon start")
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
    let output = child.wait_with_output().expect("wait for writer helper");
    drop(daemon_control);
    assert_child_success("writer", &output);
}

fn assert_child_success(role: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{role} helper failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
