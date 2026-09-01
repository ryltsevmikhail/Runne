use std::process::{Command, Output, Stdio};

#[cfg(target_os = "macos")]
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
#[cfg(target_os = "macos")]
use std::io::{IoSlice, Write as _};
#[cfg(target_os = "macos")]
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;

const BROKER_MODE: &str = "__provider-credential-broker-v1";
#[cfg(target_os = "macos")]
const RESPONSE_BYTES: usize = 160;
const UNSUPPORTED: &str = "provider credential backend is unsupported\n";
#[cfg(target_os = "macos")]
const OPERATION_FAILED: &str = "provider credential operation failed\n";

#[test]
fn broker_mode_with_extra_argument_is_rejected_before_stdin_bootstrap() {
    let output = run_with_kept_open_stdin(&[BROKER_MODE, "unexpected"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("Runne command-line interface."));
}

#[test]
#[cfg(target_os = "macos")]
fn broker_mode_without_inherited_endpoint_is_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_runne"))
        .arg(BROKER_MODE)
        .output()
        .expect("run broker mode");

    assert_closed(&output, OPERATION_FAILED);
}

#[test]
#[cfg(not(target_os = "macos"))]
fn non_macos_broker_mode_is_typed_unsupported_without_stdin() {
    let output = run_with_kept_open_stdin(&[BROKER_MODE]);

    assert_closed(&output, UNSUPPORTED);
}

#[test]
#[cfg(target_os = "macos")]
fn broker_mode_rejects_missing_descriptor() {
    let output = broker_output(&prepared_response(), &[]);
    assert_closed(&output, OPERATION_FAILED);
}

#[test]
#[cfg(target_os = "macos")]
fn broker_mode_rejects_malformed_or_trailing_response() {
    let malformed = broker_output_one(&prepared_response()[..RESPONSE_BYTES - 1]);
    assert_closed(&malformed, OPERATION_FAILED);

    let mut trailing = prepared_response().to_vec();
    trailing.push(1);
    let trailing = broker_output_one(&trailing);
    assert_closed(&trailing, OPERATION_FAILED);
}

#[test]
#[cfg(target_os = "macos")]
fn broker_mode_rejects_zero_binding_or_publication_key() {
    for range in [0..32, 96..128] {
        let mut frame = prepared_response();
        frame[range].fill(0);
        assert_closed(&broker_output_one(&frame), OPERATION_FAILED);
    }
}

#[test]
#[cfg(target_os = "macos")]
fn broker_mode_rejects_multiple_descriptors() {
    let (first, _) = UnixStream::pair().expect("first endpoint");
    let (second, _) = UnixStream::pair().expect("second endpoint");
    let output = broker_output(&prepared_response(), &[first.as_fd(), second.as_fd()]);
    assert_closed(&output, OPERATION_FAILED);
}

#[test]
#[cfg(target_os = "macos")]
fn prepared_broker_endpoint_reaches_only_unsupported_backend() {
    let output = broker_output_one(&prepared_response());
    assert_closed(&output, UNSUPPORTED);
}

#[test]
fn broker_source_has_one_authority_receive_and_no_local_receiver() {
    let broker = include_str!("../src/cli/provider_credential_broker.rs");
    assert_eq!(
        broker
            .matches("UntrustedProviderCredentialWriterEndpointHandoffV1::receive_from_stdin()")
            .count(),
        1
    );
    assert!(broker.contains("let _handoff ="));
    assert!(broker.contains("#[cfg(target_os = \"macos\")]"));
    assert!(broker.contains("#[cfg(not(target_os = \"macos\"))]"));

    let end = broker
        .find("expect_end(&arguments)?")
        .expect("argument end check");
    let receive = broker
        .find("UntrustedProviderCredentialWriterEndpointHandoffV1::receive_from_stdin()")
        .expect("authority receive");
    assert!(
        end < receive,
        "stdin must not be read before argv validation"
    );

    let sources = broker_sources();
    assert!(
        sources
            .iter()
            .any(|source| source.0.ends_with("effect_test_support/pair.rs")),
        "recursive source scan did not reach a nested broker source"
    );
    assert!(
        sources
            .iter()
            .any(|source| source.0.ends_with("/src/main.rs")),
        "source scan did not cover the complete CLI production tree"
    );
    for source in sources {
        for forbidden in ["recvmsg", "RecvAncillary", "SCM_RIGHTS", "ScmRights"] {
            assert!(
                !source.1.contains(forbidden),
                "{} retained forbidden {forbidden}",
                source.0
            );
        }
    }
    assert!(!broker.contains("mod bootstrap"));
    let removed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/cli/provider_credential_broker/bootstrap.rs");
    assert!(!removed.exists());
}

#[test]
fn broker_manifest_has_only_macos_authority_and_dev_rustix_edges() {
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("runne-macos-process-identity"));
    assert!(manifest.contains("[target.'cfg(target_os = \"macos\")'.dependencies]"));
    assert!(manifest.contains(
        "runne-native-enrollment-authority = { path = \"../runne-native-enrollment-authority\" }"
    ));
    assert!(manifest.contains("[target.'cfg(target_os = \"macos\")'.dev-dependencies]"));
    assert!(manifest.contains("rustix = { version = \"=1.1.4\", features = [\"net\"] }"));
    assert!(!manifest.contains("[target.'cfg(unix)'.dependencies]"));
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn broker_output_one(frame: &[u8]) -> Output {
    let (endpoint, _) = UnixStream::pair().expect("endpoint");
    broker_output(frame, &[endpoint.as_fd()])
}

#[cfg(target_os = "macos")]
fn prepared_response() -> [u8; RESPONSE_BYTES] {
    let mut response = [0; RESPONSE_BYTES];
    response[..32].fill(1);
    response[96..128].fill(2);
    response
}

#[cfg(target_os = "macos")]
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

fn run_with_kept_open_stdin(arguments: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_runne"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run broker mode");
    let kept_open = child.stdin.take().expect("inherited stdin pipe");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if child.try_wait().expect("poll broker process").is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("kill broker blocked on stdin");
            drop(kept_open);
            let _ = child.wait();
            panic!("broker read stdin instead of returning before the test deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect broker output");
    drop(kept_open);
    output
}

fn broker_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    collect_rust_sources(&root, &mut paths);
    paths
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path).unwrap();
            (path.display().to_string(), source)
        })
        .collect()
}

fn collect_rust_sources(directory: &std::path::Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rust_sources(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
}
