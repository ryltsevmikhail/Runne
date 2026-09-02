use std::{
    env,
    io::{Read as _, Write as _},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, Stdio},
};

use zeroize::Zeroizing;

const MODE: &str = "__slice-e-persistent-reference-probe-v1";
const RECORD_MAGIC: &[u8; 8] = b"GCPREFD1";
const MAX_REFERENCE_BYTES: usize = 1024;

pub(super) fn run() {
    super::harness::dispatch(
        "persistent_reference_locates_exact_item_without_expanding_authority",
        inner,
    );
}

fn inner(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let record = collect_writer_record(context)?;
    run_reader(context, &record)?;
    run_reader(context, &record)
}

fn collect_writer_record(
    context: &super::support::InnerContext,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let (mut parent, child) = UnixStream::pair().map_err(|_| "persistent-reference-writer-fd")?;
    let output = role_command(&context.writer(), context)
        .stdin(Stdio::from(OwnedFd::from(child)))
        .output()
        .map_err(|_| "persistent-reference-writer-launch")?;
    let mut record = Vec::with_capacity(RECORD_MAGIC.len() + 2 + MAX_REFERENCE_BYTES);
    parent
        .read_to_end(&mut record)
        .map_err(|_| "persistent-reference-writer-read")?;
    if !output.status.success() {
        return match output.stderr.as_slice() {
            b"persistent-reference-probe-populate-status:-25243\n" => {
                Err("persistent-reference-writer-populate-no-access-25243")
            }
            b"persistent-reference-probe-populate-status:-25293\n" => {
                Err("persistent-reference-writer-populate-auth-failed-25293")
            }
            b"persistent-reference-probe-populate-status:-25308\n" => {
                Err("persistent-reference-writer-populate-ui-blocked-25308")
            }
            b"persistent-reference-probe-closed-stage:item-create\n" => {
                Err("persistent-reference-writer-item-create")
            }
            b"persistent-reference-probe-closed-stage:item-finalize\n" => {
                Err("persistent-reference-writer-item-finalize")
            }
            b"persistent-reference-probe-closed-stage:item-verify-before-populate\n" => {
                Err("persistent-reference-writer-item-verify-before-populate")
            }
            b"persistent-reference-probe-closed-stage:persistent-reference-create\n" => {
                Err("persistent-reference-writer-persistent-reference-create")
            }
            _ => Err("persistent-reference-writer-status"),
        };
    }
    validate_record(&record)?;
    Ok(Zeroizing::new(record))
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
    let home = env::var_os("HOME").unwrap_or_default();
    let keychain = context
        .root()
        .join("home/Library/Keychains/runne-ci.keychain-db");
    let mut command = Command::new(path);
    command
        .arg(MODE)
        .env_clear()
        .env("HOME", home)
        .env("RUNNE_CI_MACOS_KEYCHAIN", keychain);
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}
