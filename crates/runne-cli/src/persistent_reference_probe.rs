//! Local-only writer half of the persistent-reference feasibility probe.

use std::{fs, io::Write as _};

use crate::ProcessOutcome;

pub const MODE: &str = "__slice-e-persistent-reference-probe-v1";
const RECORD_MAGIC: &[u8; 8] = b"GCPREFD1";
const MAX_REFERENCE_BYTES: usize = 1024;
const SERVICE: &str = "dev.runne.provider-credential.v1.version.1.1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT: &str = "openai";
const MARKER: &[u8] = b"persistent-reference-probe-material-v1";

#[must_use]
pub fn selected(arguments: &[std::ffi::OsString]) -> bool {
    arguments.len() == 1
        && arguments[0] == MODE
        && local_opt_in(
            std::env::var_os("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST").as_deref(),
            std::env::var_os("RUNNE_SLICE_E_INNER_CASE").as_deref(),
        )
}

fn local_opt_in(enrollment: Option<&std::ffi::OsStr>, selector: Option<&std::ffi::OsStr>) -> bool {
    enrollment == Some(std::ffi::OsStr::new("1")) && selector == Some(std::ffi::OsStr::new(MODE))
}

#[must_use]
pub fn outcome() -> ProcessOutcome {
    match run() {
        Ok(()) => ProcessOutcome {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
        Err(ProbeError::Populate(status)) => ProcessOutcome {
            stdout: String::new(),
            stderr: format!("persistent-reference-probe-populate-status:{status}\n"),
            exit_code: 1,
        },
        Err(ProbeError::Closed(stage)) => ProcessOutcome {
            stdout: String::new(),
            stderr: format!("persistent-reference-probe-closed-stage:{stage}\n"),
            exit_code: 1,
        },
    }
}

enum ProbeError {
    Closed(&'static str),
    Populate(i32),
}

fn run() -> Result<(), ProbeError> {
    let fixture = runne_macos_keychain_acl::current_persistent_reference_fixture(
        runne_macos_keychain_acl::PersistentReferenceProbeRole::Writer,
        MODE,
    )
    .map_err(|_| ProbeError::Closed("fixture"))?;
    runne_native_enrollment_authority::validate_persistent_reference_parent_channel(
        fixture.parent_pid(),
    )
    .map_err(|_| ProbeError::Closed("parent-channel"))?;
    let (_interaction, keychain) =
        runne_macos_keychain_acl::open_noninteractive_keychain(fixture.keychain())
            .map_err(|_| ProbeError::Closed("keychain-open"))?;
    let access =
        runne_macos_keychain_acl::ExactKeychainAccess::new(fixture.writer(), fixture.reader())
            .map_err(|_| ProbeError::Closed("access"))?;
    let metadata = metadata();
    let item = runne_macos_keychain_acl::create_empty_generic_password(
        &keychain, SERVICE, ACCOUNT, &metadata, &access,
    )
    .map_err(|_| ProbeError::Closed("item-create"))?;
    let mut item = item.finalize(&access).map_err(|error| match error {
        runne_macos_keychain_acl::KeychainAclError::AccessDenied => {
            ProbeError::Closed("item-finalize-access-denied")
        }
        _ => ProbeError::Closed("item-finalize"),
    })?;
    let reference = (|| {
        runne_macos_keychain_acl::verify_item_access(&item, access.digest())
            .map_err(|_| ProbeError::Closed("item-verify-before-populate"))?;
        runne_macos_keychain_acl::set_item_password_with_status(&mut item, MARKER)
            .map_err(ProbeError::Populate)?;
        runne_macos_keychain_acl::verify_item_access(&item, access.digest())
            .map_err(|_| ProbeError::Closed("item-verify-after-populate"))?;
        runne_macos_keychain_acl::create_persistent_reference(&item)
            .map(runne_macos_keychain_acl::PersistentKeychainReference::into_bytes)
            .map_err(|_| ProbeError::Closed("persistent-reference-create"))
    })();
    match reference {
        Ok(reference) => match send_record(&reference) {
            Ok(()) => Ok(()),
            Err(()) => {
                if runne_macos_keychain_acl::delete_item(&item).is_err() {
                    Err(ProbeError::Closed("item-cleanup"))
                } else {
                    Err(ProbeError::Closed("record-send"))
                }
            }
        },
        Err(error) => {
            if runne_macos_keychain_acl::delete_item(&item).is_err() {
                Err(ProbeError::Closed("item-cleanup"))
            } else {
                Err(error)
            }
        }
    }
}

fn metadata() -> [u8; 55] {
    let mut bytes = [0_u8; 55];
    bytes[..8].copy_from_slice(b"GCPREF1\0");
    bytes[8..14].copy_from_slice(b"openai");
    bytes[14..22].copy_from_slice(&1_u64.to_be_bytes());
    bytes[22..54].fill(0x11);
    bytes[54] = 1;
    bytes
}

fn send_record(reference: &zeroize::Zeroizing<Vec<u8>>) -> Result<(), ()> {
    if reference.is_empty() || reference.len() > MAX_REFERENCE_BYTES {
        return Err(());
    }
    let length = u16::try_from(reference.len()).map_err(|_| ())?;
    let mut channel = duplicate_stdin()?;
    channel.write_all(RECORD_MAGIC).map_err(|_| ())?;
    channel.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    channel
        .write_all(reference)
        .and_then(|()| channel.flush())
        .map_err(|_| ())
}

fn duplicate_stdin() -> Result<fs::File, ()> {
    nix::unistd::dup(std::io::stdin())
        .map(fs::File::from)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_requires_explicit_local_opt_in() {
        assert!(!selected(&[MODE.into()]));
        assert!(!selected(&[MODE.into(), "reference".into()]));
        assert!(!local_opt_in(None, None));
        assert!(!local_opt_in(Some("1".as_ref()), Some("wrong".as_ref())));
        assert!(local_opt_in(Some("1".as_ref()), Some(MODE.as_ref())));
        assert_eq!(RECORD_MAGIC.len(), 8);
        assert!(MAX_REFERENCE_BYTES <= 1024);
    }
}
