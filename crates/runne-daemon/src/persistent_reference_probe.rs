//! Local-only reader half of the persistent-reference feasibility probe.

use std::{fs, os::fd::AsFd as _};

use zeroize::{Zeroize as _, Zeroizing};

pub const MODE: &str = "__slice-e-persistent-reference-probe-v1";
const RECORD_MAGIC: &[u8; 8] = b"GCPREFD1";
const MAX_REFERENCE_BYTES: usize = 1024;
const RECORD_HEADER_BYTES: usize = RECORD_MAGIC.len() + 2;
const SERVICE: &str = "dev.runne.provider-credential.v1.version.1.1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT: &str = "openai";
const MARKER: &[u8] = b"persistent-reference-probe-material-v1";

/// Closed failure returned by the local-only feasibility probe.
#[derive(Debug)]
pub struct ProbeError;

impl From<()> for ProbeError {
    fn from((): ()) -> Self {
        Self
    }
}

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

pub fn run() -> Result<(), ProbeError> {
    let fixture = runne_macos_keychain_acl::current_persistent_reference_fixture(
        runne_macos_keychain_acl::PersistentReferenceProbeRole::Reader,
        MODE,
    )
    .map_err(|_| ())?;
    runne_native_enrollment_authority::validate_persistent_reference_parent_channel(
        fixture.parent_pid(),
    )
    .map_err(|_| ())?;
    let (_interaction, keychain) =
        runne_macos_keychain_acl::open_noninteractive_keychain(fixture.keychain())
            .map_err(|_| ())?;
    let reference = receive_record()?;
    let item = runne_macos_keychain_acl::resolve_persistent_reference(reference.as_slice())
        .map_err(|_| ())?;
    let access =
        runne_macos_keychain_acl::ExactKeychainAccess::new(fixture.writer(), fixture.reader())
            .map_err(|_| ())?;
    runne_macos_keychain_acl::verify_persistent_reference_item(
        &item,
        &keychain,
        SERVICE,
        ACCOUNT,
        &metadata(),
        access.digest(),
    )
    .map_err(|_| ())?;
    let material =
        runne_macos_keychain_acl::copy_persistent_reference_password(&item).map_err(|_| ())?;
    (material.as_slice() == MARKER)
        .then_some(())
        .ok_or(ProbeError)
}

fn receive_record() -> Result<ReceivedReference, ()> {
    let duplicate = rustix::io::dup(std::io::stdin().as_fd()).map_err(|_| ())?;
    let mut channel = fs::File::from(duplicate);
    receive_record_from(&mut channel)
}

fn receive_record_from(channel: &mut impl std::io::Read) -> Result<ReceivedReference, ()> {
    let mut reference = ReceivedReference {
        bytes: Zeroizing::new(Vec::new()),
    };
    reference
        .bytes
        .try_reserve(RECORD_HEADER_BYTES + MAX_REFERENCE_BYTES + 1)
        .map_err(|_| ())?;
    reference.bytes.resize(RECORD_HEADER_BYTES, 0);
    channel.read_exact(&mut reference.bytes).map_err(|_| ())?;
    let length = usize::from(u16::from_be_bytes([reference.bytes[8], reference.bytes[9]]));
    if reference.bytes[..RECORD_MAGIC.len()] != *RECORD_MAGIC
        || length == 0
        || length > MAX_REFERENCE_BYTES
    {
        return Err(());
    }
    let end = RECORD_HEADER_BYTES + length;
    reference.bytes.resize(end + 1, 0);
    channel
        .read_exact(&mut reference.bytes[RECORD_HEADER_BYTES..end])
        .map_err(|_| ())?;
    if channel.read(&mut reference.bytes[end..]).map_err(|_| ())? != 0 {
        return Err(());
    }
    reference.bytes.truncate(end);
    Ok(reference)
}

struct ReceivedReference {
    bytes: Zeroizing<Vec<u8>>,
}

impl ReceivedReference {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[RECORD_HEADER_BYTES..]
    }
}

impl Drop for ReceivedReference {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        FRAME_ZEROIZATION_OBSERVED
            .with(|observed| observed.set(self.bytes.iter().all(|byte| *byte == 0)));
    }
}

#[cfg(test)]
thread_local! {
    static FRAME_ZEROIZATION_OBSERVED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn reset_framing_zeroization_observer() {
    FRAME_ZEROIZATION_OBSERVED.with(|observed| observed.set(false));
}

#[cfg(test)]
fn framing_zeroization_observed() -> bool {
    FRAME_ZEROIZATION_OBSERVED.with(std::cell::Cell::get)
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
    use std::io::Cursor;

    use super::*;

    const _: () = assert!(MAX_REFERENCE_BYTES <= 1024);

    #[test]
    fn mode_and_metadata_are_exact_and_bounded() {
        assert!(!selected(&[MODE.into()]));
        assert!(!selected(&[MODE.into(), "reference".into()]));
        assert!(!local_opt_in(None, None));
        assert!(!local_opt_in(Some("1".as_ref()), Some("wrong".as_ref())));
        assert!(local_opt_in(Some("1".as_ref()), Some(MODE.as_ref())));
        assert_eq!(RECORD_MAGIC.len(), 8);
        assert_eq!(metadata()[54], 1);
    }

    #[test]
    fn record_reader_zeroizes_the_first_owned_locator_buffer_and_rejects_bad_framing() {
        let mut truncated = Cursor::new([RECORD_MAGIC.as_slice(), &[0, 2], &[7]].concat());
        assert!(receive_record_from(&mut truncated).is_err());
        let mut trailing = Cursor::new([RECORD_MAGIC.as_slice(), &[0, 1], &[7, 8]].concat());
        assert!(receive_record_from(&mut trailing).is_err());
        let mut malformed = Cursor::new([b"wrongref".as_slice(), &[0, 1], &[7]].concat());
        assert!(receive_record_from(&mut malformed).is_err());
        let mut valid = Cursor::new([RECORD_MAGIC.as_slice(), &[0, 1], &[7]].concat());
        assert_eq!(receive_record_from(&mut valid).unwrap().as_slice(), &[7]);
    }

    #[test]
    fn framing_bytes_are_zeroized_after_malformed_trailing_and_successful_records() {
        reset_framing_zeroization_observer();
        let mut malformed = Cursor::new([b"wrongref".as_slice(), &[0, 1], &[7]].concat());
        assert!(receive_record_from(&mut malformed).is_err());
        assert!(framing_zeroization_observed());
        reset_framing_zeroization_observer();
        let mut trailing = Cursor::new([RECORD_MAGIC.as_slice(), &[0, 1], &[7, 8]].concat());
        assert!(receive_record_from(&mut trailing).is_err());
        assert!(framing_zeroization_observed());
        reset_framing_zeroization_observer();
        let mut valid = Cursor::new([RECORD_MAGIC.as_slice(), &[0, 1], &[7]].concat());
        let reference = receive_record_from(&mut valid).unwrap();
        assert!(!framing_zeroization_observed());
        drop(reference);
        assert!(framing_zeroization_observed());
    }
}
