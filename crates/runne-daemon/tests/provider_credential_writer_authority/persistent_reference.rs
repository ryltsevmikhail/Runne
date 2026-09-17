use std::os::unix::net::UnixListener;
use std::time::Duration;
use std::{
    fs,
    io::{Read as _, Write as _},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, Stdio},
};

use zeroize::Zeroizing;

const MODE: &str = "__slice-e-persistent-reference-probe-v1";
const RECORD_MAGIC: &[u8; 8] = b"GCPREFD1";
const MAX_REFERENCE_BYTES: usize = 1024;
const UNRELATED_PEER_SOCKET: &str = "RUNNE_SLICE_E_UNRELATED_PEER_SOCKET";

pub(super) fn run() {
    super::harness::dispatch(
        "persistent_reference_is_bounded_or_fails_closed_on_native_acl_rewrite",
        inner,
    );
}

pub(super) fn unrelated_peer_run() {
    super::harness::dispatch(
        "persistent_reference_rejects_unrelated_same_uid_peer",
        unrelated_peer_inner,
    );
}

fn inner(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let record = match collect_writer_record(context) {
        Ok(record) => record,
        Err("persistent-reference-writer-item-finalize-access-denied") => {
            return super::native_item::assert_absent(context.root());
        }
        Err(error) => return Err(error),
    };
    run_reader(context, &record)?;
    run_reader(context, &record)
}

fn unrelated_peer_inner(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let socket = std::path::PathBuf::from(format!("/tmp/runne-u-{}", std::process::id()));
    let listener = UnixListener::bind(&socket).map_err(|_| "unrelated-peer-listener")?;
    let mut unrelated = Command::new(std::env::current_exe().map_err(|_| "unrelated-peer-self")?)
        .args(["--exact", "persistent_reference::unrelated_peer_holder"])
        .env_clear()
        .env(UNRELATED_PEER_SOCKET, &socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "unrelated-peer-launch")?;
    let output = listener
        .accept()
        .map_err(|_| "unrelated-peer-accept")
        .and_then(|(parent, _)| {
            role_command(&context.writer(), context)
                .stdin(Stdio::from(OwnedFd::from(parent)))
                .output()
                .map_err(|_| "unrelated-peer-writer-launch")
        });
    let cleanup = unrelated
        .kill()
        .and_then(|()| unrelated.wait())
        .map_err(|_| "unrelated-peer-cleanup");
    drop(listener);
    let socket_cleanup = fs::remove_file(socket).map_err(|_| "unrelated-peer-socket-cleanup");
    let output = output?;
    cleanup?;
    socket_cleanup?;
    match output.stderr.as_slice() {
        b"persistent-reference-probe-closed-stage:parent-channel\n" => Ok(()),
        b"persistent-reference-probe-closed-stage:item-finalize\n" => {
            Err("unrelated-peer-accepted-item-finalize")
        }
        b"persistent-reference-probe-closed-stage:fixture\n" => Err("unrelated-peer-fixture"),
        _ => Err("unrelated-peer-not-rejected"),
    }
}

#[test]
fn unrelated_peer_holder() {
    let Ok(socket) = std::env::var(UNRELATED_PEER_SOCKET) else {
        return;
    };
    let _peer = UnixStream::connect(socket).unwrap();
    std::thread::sleep(Duration::from_secs(10));
}

fn collect_writer_record(
    context: &super::support::InnerContext,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let (mut parent, child) = UnixStream::pair().map_err(|_| "persistent-reference-writer-fd")?;
    let output = role_command(&context.writer(), context)
        .stdin(Stdio::from(OwnedFd::from(child)))
        .output()
        .map_err(|_| "persistent-reference-writer-launch")?;
    let record = read_writer_record(&mut parent)?;
    if !output.status.success() {
        return match output.stderr.as_slice() {
            b"persistent-reference-probe-closed-stage:item-create\n" => {
                Err("persistent-reference-writer-item-create")
            }
            b"persistent-reference-probe-closed-stage:fixture\n" => {
                Err("persistent-reference-writer-fixture")
            }
            b"persistent-reference-probe-closed-stage:parent-channel\n" => {
                Err("persistent-reference-writer-parent-channel")
            }
            b"persistent-reference-probe-closed-stage:keychain-open\n" => {
                Err("persistent-reference-writer-keychain-open")
            }
            b"persistent-reference-probe-closed-stage:access\n" => {
                Err("persistent-reference-writer-access")
            }
            b"persistent-reference-probe-closed-stage:item-finalize\n" => {
                Err("persistent-reference-writer-item-finalize")
            }
            b"persistent-reference-probe-closed-stage:item-finalize-access-denied\n" => {
                Err("persistent-reference-writer-item-finalize-access-denied")
            }
            b"persistent-reference-probe-closed-stage:persistent-reference-create\n" => {
                Err("persistent-reference-writer-persistent-reference-create")
            }
            b"persistent-reference-probe-closed-stage:record-send\n" => {
                Err("persistent-reference-writer-record-send")
            }
            b"persistent-reference-probe-closed-stage:item-cleanup\n" => {
                Err("persistent-reference-writer-item-cleanup")
            }
            _ => Err("persistent-reference-writer-status"),
        };
    }
    validate_record(&record)?;
    Ok(record)
}

fn read_writer_record(reader: &mut impl std::io::Read) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut record = Zeroizing::new(Vec::new());
    record
        .try_reserve(RECORD_MAGIC.len() + 2 + MAX_REFERENCE_BYTES + 1)
        .map_err(|_| "persistent-reference-writer-buffer")?;
    let limit = u64::try_from(RECORD_MAGIC.len() + 2 + MAX_REFERENCE_BYTES + 1)
        .map_err(|_| "persistent-reference-writer-bound")?;
    reader
        .take(limit)
        .read_to_end(&mut record)
        .map_err(|_| "persistent-reference-writer-read")?;
    if record.len() == usize::try_from(limit).map_err(|_| "persistent-reference-writer-bound")? {
        return Err("persistent-reference-record-overlong");
    }
    Ok(record)
}

fn run_reader(context: &super::support::InnerContext, record: &[u8]) -> Result<(), &'static str> {
    let (mut parent, child) = UnixStream::pair().map_err(|_| "persistent-reference-reader-fd")?;
    let mut reader = role_command(context.daemon(), context)
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "persistent-reference-reader-launch")?;
    parent
        .write_all(record)
        .and_then(|()| parent.shutdown(Shutdown::Write))
        .map_err(|_| "persistent-reference-reader-write")?;
    reader
        .wait()
        .map_err(|_| "persistent-reference-reader-wait")?
        .success()
        .then_some(())
        .ok_or("persistent-reference-reader-status")
}

fn role_command(path: &std::path::Path, context: &super::support::InnerContext) -> Command {
    let home = context.root().join("home");
    let keychain = context
        .root()
        .join("home/Library/Keychains/runne-ci.keychain-db");
    let mut command = Command::new(path);
    command
        .arg(MODE)
        .env_clear()
        .env("HOME", home)
        .env("RUNNE_CI_MACOS_KEYCHAIN", keychain)
        .env("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST", "1")
        .env("RUNNE_SLICE_E_INNER_CASE", MODE)
        .env("RUNNE_SLICE_E_FIXTURE_ROOT", context.root());
    command
}

fn validate_record(record: &[u8]) -> Result<(), &'static str> {
    if record.len() < RECORD_MAGIC.len() + 2 || record[..8] != *RECORD_MAGIC {
        return Err("persistent-reference-record-header");
    }
    let length = usize::from(u16::from_be_bytes([record[8], record[9]]));
    if length == 0 || length > MAX_REFERENCE_BYTES || record.len() != 10 + length {
        return Err("persistent-reference-record-shape");
    }
    Ok(())
}

#[test]
fn parent_record_buffer_rejects_malformed_truncated_trailing_and_overlong_input() {
    let mut malformed = std::io::Cursor::new(b"not-a-record".to_vec());
    assert_eq!(
        read_writer_record(&mut malformed).and_then(|record| validate_record(&record)),
        Err("persistent-reference-record-header")
    );
    let mut truncated = std::io::Cursor::new([RECORD_MAGIC.as_slice(), &[0, 2], &[3]].concat());
    assert_eq!(
        read_writer_record(&mut truncated).and_then(|record| validate_record(&record)),
        Err("persistent-reference-record-shape")
    );
    let mut trailing = std::io::Cursor::new([RECORD_MAGIC.as_slice(), &[0, 1], &[3, 4]].concat());
    assert_eq!(
        read_writer_record(&mut trailing).and_then(|record| validate_record(&record)),
        Err("persistent-reference-record-shape")
    );
    let mut overlong =
        std::io::Cursor::new(vec![0_u8; RECORD_MAGIC.len() + 3 + MAX_REFERENCE_BYTES]);
    assert_eq!(
        read_writer_record(&mut overlong),
        Err("persistent-reference-record-overlong")
    );
}

#[test]
fn native_fd_probe_has_no_public_or_durable_reference_sink() {
    let writer = include_bytes!("../../../runne-cli/src/persistent_reference_probe.rs");
    let reader = include_bytes!("../../src/persistent_reference_probe.rs");
    for source in [writer.as_slice(), reader.as_slice()] {
        for forbidden in [
            b"serde".as_slice(),
            b"sqlite".as_slice(),
            b"http".as_slice(),
            b"tauri".as_slice(),
            b"File::create".as_slice(),
            b"std::fs::write".as_slice(),
            b"std::env::args".as_slice(),
        ] {
            assert!(!contains(source, forbidden));
        }
    }
    for forbidden in [
        b"set_item_password".as_slice(),
        b"delete_item".as_slice(),
        b"set_generic_password".as_slice(),
        b"SecKeychainItemModifyAttributesAndData".as_slice(),
        b"SecKeychainItemSetAccess".as_slice(),
    ] {
        assert!(!contains(reader, forbidden));
    }
}

#[test]
fn native_fd_probe_requires_coupled_features_and_package_fixture_preflight() {
    let writer_manifest = include_bytes!("../../../runne-cli/Cargo.toml");
    let reader_manifest = include_bytes!("../../Cargo.toml");
    assert!(contains(
        writer_manifest,
        b"persistent-reference-probe = [\n    \"local-native-enrollment-test\"",
    ));
    assert!(contains(
        reader_manifest,
        b"persistent-reference-probe = [\n    \"test-support\",\n    \"desktop-protected\"",
    ));
    let writer = include_bytes!("../../../runne-cli/src/persistent_reference_probe.rs");
    let reader = include_bytes!("../../src/persistent_reference_probe.rs");
    for source in [writer.as_slice(), reader.as_slice()] {
        assert!(contains(source, b"current_persistent_reference_fixture"));
        assert!(contains(
            source,
            b"validate_persistent_reference_parent_channel",
        ));
        assert!(contains(source, b"RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST"));
        assert!(contains(source, b"RUNNE_SLICE_E_INNER_CASE"));
    }
    let fixture = include_bytes!(
        "../../../runne-macos-keychain-acl/src/implementation_parts/persistent_reference_fixture.inc",
    );
    let writer = include_bytes!("../../../runne-cli/src/persistent_reference_probe.rs");
    let reader = include_bytes!("../../src/persistent_reference_probe.rs");
    for role in [writer.as_slice(), reader.as_slice()] {
        assert!(contains(
            role,
            b"runne_native_enrollment_authority::validate_persistent_reference_parent_channel",
        ));
    }
    assert!(contains(fixture, b"pub const fn parent_pid"));
    assert!(!contains(fixture, b"MacOsLocalPeerProcessIdentity"));
}
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}
