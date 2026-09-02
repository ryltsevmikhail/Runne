//! Local-only writer half of the persistent-reference feasibility probe.

use std::{fs, io::Write as _, os::fd::AsFd as _, path::PathBuf};

use crate::ProcessOutcome;

pub(super) const MODE: &str = "__slice-e-persistent-reference-probe-v1";
const RECORD_MAGIC: &[u8; 8] = b"GCPREFD1";
const MAX_REFERENCE_BYTES: usize = 1024;
const SERVICE: &str = "dev.runne.provider-credential.v1.version.1.1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT: &str = "openai";
const MARKER: &[u8] = b"persistent-reference-probe-material-v1";

pub(super) fn selected(arguments: &[std::ffi::OsString]) -> bool {
    arguments.len() == 1 && arguments[0] == MODE
}

pub(super) fn outcome() -> ProcessOutcome {
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
    let (keychain_path, writer, reader) =
        owned_context().map_err(|_| ProbeError::Closed("context"))?;
    let (_interaction, keychain) =
        runne_macos_keychain_acl::open_noninteractive_keychain(&keychain_path)
            .map_err(|_| ProbeError::Closed("keychain-open"))?;
    let access = runne_macos_keychain_acl::ExactKeychainAccess::new(&writer, &reader)
        .map_err(|_| ProbeError::Closed("access"))?;
    let metadata = metadata();
    let item = runne_macos_keychain_acl::create_empty_generic_password(
        &keychain, SERVICE, ACCOUNT, &metadata, &access,
    )
    .map_err(|_| ProbeError::Closed("item-create"))?;
    let mut item = item
        .finalize(&access)
        .map_err(|_| ProbeError::Closed("item-finalize"))?;
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
        Ok(reference) => match send_record(reference) {
            Ok(()) => Ok(()),
            Err(()) => {
                let _ = runne_macos_keychain_acl::delete_item(&item);
                Err(ProbeError::Closed("record-send"))
            }
        },
        Err(error) => {
            let _ = runne_macos_keychain_acl::delete_item(&item);
            Err(error)
        }
    }
}

fn owned_context() -> Result<(PathBuf, PathBuf, PathBuf), ()> {
    let current = fs::canonicalize(std::env::current_exe().map_err(|_| ())?).map_err(|_| ())?;
    let macos = current.parent().ok_or(())?;
    if current.file_name().is_none_or(|name| name != "runne") {
        return Err(());
    }
    let contents = macos.parent().ok_or(())?;
    let application = contents.parent().ok_or(())?;
    let root = application.parent().ok_or(())?.to_owned();
    if application
        .file_name()
        .is_none_or(|name| name != "Runne.app")
    {
        return Err(());
    }
    let keychain = root.join("home/Library/Keychains/runne-ci.keychain-db");
    if std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN").as_deref() != Some(keychain.as_os_str()) {
        return Err(());
    }
    let reader = macos.join("runned");
    if !keychain.is_file() || !reader.is_file() {
        return Err(());
    }
    Ok((keychain, current, reader))
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

fn send_record(reference: zeroize::Zeroizing<Vec<u8>>) -> Result<(), ()> {
    if reference.is_empty() || reference.len() > MAX_REFERENCE_BYTES {
        return Err(());
    }
    let length = u16::try_from(reference.len()).map_err(|_| ())?;
    let duplicate = rustix::io::dup(std::io::stdin().as_fd()).map_err(|_| ())?;
    let mut channel = fs::File::from(duplicate);
    channel.write_all(RECORD_MAGIC).map_err(|_| ())?;
    channel.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    channel
        .write_all(&reference)
        .and_then(|()| channel.flush())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_has_no_reference_input_surface() {
        assert!(selected(&[MODE.into()]));
        assert!(!selected(&[MODE.into(), "reference".into()]));
        assert_eq!(RECORD_MAGIC.len(), 8);
        assert!(MAX_REFERENCE_BYTES <= 1024);
    }
}
