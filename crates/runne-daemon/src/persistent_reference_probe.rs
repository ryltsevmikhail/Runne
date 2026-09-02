//! Local-only reader half of the persistent-reference feasibility probe.

use std::{
    fs,
    io::Read as _,
    os::fd::AsFd as _,
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

pub(super) const MODE: &str = "__slice-e-persistent-reference-probe-v1";
const RECORD_MAGIC: &[u8; 8] = b"GCPREFD1";
const MAX_REFERENCE_BYTES: usize = 1024;
const SERVICE: &str = "dev.runne.provider-credential.v1.version.1.1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT: &str = "openai";
const MARKER: &[u8] = b"persistent-reference-probe-material-v1";

pub(super) fn selected(arguments: &[std::ffi::OsString]) -> bool {
    arguments.len() == 1 && arguments[0] == MODE
}

pub(super) fn run() -> Result<(), ()> {
    let (keychain_path, writer, reader) = owned_context()?;
    let (_interaction, keychain) =
        runne_macos_keychain_acl::open_noninteractive_keychain(&keychain_path).map_err(|_| ())?;
    current_reader_identity(&reader)?;
    let reference = receive_record()?;
    let item =
        runne_macos_keychain_acl::resolve_persistent_reference(&reference).map_err(|_| ())?;
    let access =
        runne_macos_keychain_acl::ExactKeychainAccess::new(&writer, &reader).map_err(|_| ())?;
    runne_macos_keychain_acl::verify_persistent_reference_item(
        &item,
        &keychain,
        SERVICE,
        ACCOUNT,
        &metadata(),
        access.digest(),
    )
    .map_err(|_| ())?;
    let material = Zeroizing::new(
        runne_macos_keychain_acl::copy_persistent_reference_password(&item).map_err(|_| ())?,
    );
    (material.as_slice() == MARKER).then_some(()).ok_or(())
}

fn owned_context() -> Result<(PathBuf, PathBuf, PathBuf), ()> {
    let current = fs::canonicalize(std::env::current_exe().map_err(|_| ())?).map_err(|_| ())?;
    if current.file_name().is_none_or(|name| name != "runned") {
        return Err(());
    }
    let macos = current.parent().ok_or(())?;
    let contents = macos.parent().ok_or(())?;
    let application = contents.parent().ok_or(())?;
    let root = application.parent().ok_or(())?;
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
    let writer = macos.join("runne");
    if !keychain.is_file() || !writer.is_file() {
        return Err(());
    }
    Ok((keychain, writer, current))
}

fn current_reader_identity(reader: &Path) -> Result<(), ()> {
    let current = fs::canonicalize(std::env::current_exe().map_err(|_| ())?).map_err(|_| ())?;
    let expected = fs::canonicalize(reader).map_err(|_| ())?;
    let current = runne_api::ExecutableIdentityV1::measure(&current).map_err(|_| ())?;
    let expected = runne_api::ExecutableIdentityV1::measure(&expected).map_err(|_| ())?;
    (current == expected).then_some(()).ok_or(())
}

fn receive_record() -> Result<Zeroizing<Vec<u8>>, ()> {
    let duplicate = rustix::io::dup(std::io::stdin().as_fd()).map_err(|_| ())?;
    let mut channel = fs::File::from(duplicate);
    let mut magic = [0_u8; 8];
    let mut length = [0_u8; 2];
    channel.read_exact(&mut magic).map_err(|_| ())?;
    channel.read_exact(&mut length).map_err(|_| ())?;
    let length = usize::from(u16::from_be_bytes(length));
    if magic != *RECORD_MAGIC || length == 0 || length > MAX_REFERENCE_BYTES {
        return Err(());
    }
    let mut reference = vec![0_u8; length];
    channel.read_exact(&mut reference).map_err(|_| ())?;
    let mut extra = [0_u8; 1];
    (channel.read(&mut extra).map_err(|_| ())? == 0)
        .then_some(Zeroizing::new(reference))
        .ok_or(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_and_metadata_are_exact_and_bounded() {
        assert!(selected(&[MODE.into()]));
        assert!(!selected(&[MODE.into(), "reference".into()]));
        assert_eq!(RECORD_MAGIC.len(), 8);
        assert!(MAX_REFERENCE_BYTES <= 1024);
        assert_eq!(metadata()[54], 1);
    }
}
