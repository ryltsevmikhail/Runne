#![cfg(unix)]

use std::io::{IoSlice, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Command, Output, Stdio};

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

const BROKER_MODE: &str = "__provider-credential-broker-v1";
const RESPONSE_BYTES: usize = 160;
const UNSUPPORTED: &str = "provider credential backend is unsupported\n";
const OPERATION_FAILED: &str = "provider credential operation failed\n";

#[test]
fn broker_mode_with_extra_argument_is_rejected_before_stdin_bootstrap() {
    let output = Command::new(env!("CARGO_BIN_EXE_runne"))
        .args([BROKER_MODE, "unexpected"])
        .output()
        .expect("run broker mode");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("Runne command-line interface."));
}

#[test]
fn broker_mode_without_inherited_endpoint_is_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_runne"))
        .arg(BROKER_MODE)
        .output()
        .expect("run broker mode");

    assert_closed(&output, OPERATION_FAILED);
}

#[test]
fn broker_mode_rejects_missing_descriptor() {
    let output = broker_output(&prepared_response(), &[]);
    assert_closed(&output, OPERATION_FAILED);
}

#[test]
fn broker_mode_rejects_malformed_or_trailing_response() {
    let malformed = broker_output_one(&prepared_response()[..RESPONSE_BYTES - 1]);
    assert_closed(&malformed, OPERATION_FAILED);

    let mut trailing = prepared_response().to_vec();
    trailing.push(1);
    let trailing = broker_output_one(&trailing);
    assert_closed(&trailing, OPERATION_FAILED);
}

#[test]
fn broker_mode_rejects_multiple_descriptors() {
    let (first, _) = UnixStream::pair().expect("first endpoint");
    let (second, _) = UnixStream::pair().expect("second endpoint");
    let output = broker_output(&prepared_response(), &[first.as_fd(), second.as_fd()]);
    assert_closed(&output, OPERATION_FAILED);
}

#[test]
fn prepared_broker_endpoint_reaches_only_unsupported_backend() {
    let output = broker_output_one(&prepared_response());
    assert_closed(&output, UNSUPPORTED);
}

#[test]
fn broker_dispatch_is_before_tokio_runtime_construction() {
    let source = include_str!("../src/main.rs");
    let broker = source
        .find("run_provider_credential_broker(VecDeque::from(arguments))")
        .expect("synchronous broker branch");
    let runtime = source
        .find("tokio::runtime::Runtime::new")
        .expect("async runtime construction");
    assert!(broker < runtime);
}

fn broker_output(frame: &[u8], descriptors: &[BorrowedFd<'_>]) -> Output {
    let (mut sender, receiver) = UnixStream::pair().expect("stdin transport");
    if descriptors.is_empty() {
        sender
            .write_all(frame)
            .expect("write descriptor-free frame");
    } else {
        send_response(&mut sender, frame, descriptors);
    }
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("close transport");
    Command::new(env!("CARGO_BIN_EXE_runne"))
        .arg(BROKER_MODE)
        .stdin(Stdio::from(OwnedFd::from(receiver)))
        .output()
        .expect("run broker mode")
}

fn broker_output_one(frame: &[u8]) -> Output {
    let (endpoint, _) = UnixStream::pair().expect("endpoint");
    broker_output(frame, &[endpoint.as_fd()])
}

fn prepared_response() -> [u8; RESPONSE_BYTES] {
    let mut response = [0; RESPONSE_BYTES];
    response[..32].fill(1);
    response[96..128].fill(2);
    response
}

fn send_response(transport: &mut UnixStream, frame: &[u8], descriptors: &[BorrowedFd<'_>]) {
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(descriptors)));
    let sent = sendmsg(
        transport,
        &[IoSlice::new(frame)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .expect("send response");
    assert_eq!(sent, frame.len());
}

fn assert_closed(output: &Output, expected_stderr: &str) {
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(String::from_utf8_lossy(&output.stderr), expected_stderr);
}
