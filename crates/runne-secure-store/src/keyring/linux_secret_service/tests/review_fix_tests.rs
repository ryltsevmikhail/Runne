//! Review-fix tests: documented absent mapping + SS fallback (M1), rollback
//! double-faults (M2), mismatch-cleanup residue (M3), DH trivial elements
//! (L1), derived-address validation (L2).

use super::fake_bus::FakeSecretServiceBus;
use super::fake_cache::FakeKeyutilsCache;
use super::fake_support::FakeProcessFacts;
use crate::keyring::linux_secret_service::cache::{self, kernel_absent};
use crate::keyring::linux_secret_service::combo::{ComboError, LinuxComboPersistentStore};
use crate::keyring::linux_secret_service::dh_session::DhSession;
use crate::keyring::linux_secret_service::item_layout::EntryIdentity;
use crate::keyring::linux_secret_service::libdbus::{
    derived_session_bus_address, validate_derived_session_bus_address,
};
use crate::keyring::linux_secret_service::port::SsBusError;

const SERVICE: &str = "dev.runne.provider-credential.v1";
const ACCOUNT: &str = "deepseek";

fn identity() -> EntryIdentity {
    EntryIdentity::new(SERVICE, ACCOUNT)
}

fn entry_attributes() -> [(&'static str, &'static str); 4] {
    [
        ("service", SERVICE),
        ("username", ACCOUNT),
        ("target", "default"),
        ("application", "rust-keyring"),
    ]
}

fn store() -> LinuxComboPersistentStore<FakeSecretServiceBus, FakeProcessFacts, FakeKeyutilsCache> {
    LinuxComboPersistentStore::new(
        FakeSecretServiceBus::new(),
        FakeProcessFacts::new(),
        FakeKeyutilsCache::new(),
    )
    .expect("bound")
}

#[test]
fn kernel_absent_matches_documented_keyutils_semantics() {
    use linux_keyutils::KeyError;
    assert!(kernel_absent(KeyError::KeyDoesNotExist));
    assert!(kernel_absent(KeyError::AccessDenied));
    assert!(kernel_absent(KeyError::KeyRevoked));
    assert!(kernel_absent(KeyError::KeyExpired));
    assert!(!kernel_absent(KeyError::PermissionDenied));
    assert!(!kernel_absent(KeyError::InvalidDescription));
}

#[test]
fn cache_get_failure_falls_back_to_authoritative_ss_half() {
    let mut bus = FakeSecretServiceBus::new();
    bus.add_item(&entry_attributes(), b"persisted", false);
    let mut combo =
        LinuxComboPersistentStore::new(bus, FakeProcessFacts::new(), FakeKeyutilsCache::new())
            .expect("bound");
    combo.cache_mut().fail_get = true;
    let read = combo
        .read_dispatch(&identity())
        .expect("accelerator failure does not block the SS half")
        .expect("present");
    assert_eq!(&*read, b"persisted");
}

#[test]
fn ss_write_failure_with_failed_restore_is_distinct_rollback_error() {
    let mut combo = store();
    combo
        .cache_mut()
        .seed(&cache::entry_description(SERVICE, ACCOUNT), b"previous");
    combo.cache_mut().fail_restore = true;
    combo.bus_mut().connect_fails = true;
    let error = combo
        .write_persisted(&identity(), b"next")
        .err()
        .expect("double fault");
    assert_eq!(error, ComboError::RollbackRestoreFailed);
}

#[test]
fn ss_write_failure_with_failed_delete_is_distinct_rollback_error() {
    let mut combo = store();
    combo.cache_mut().fail_delete_after_set = true;
    combo.bus_mut().connect_fails = true;
    let error = combo
        .write_persisted(&identity(), b"next")
        .err()
        .expect("double fault");
    assert_eq!(error, ComboError::RollbackDeleteFailed);
}

#[test]
fn mismatch_cleanup_with_failing_ss_delete_is_cleanup_incomplete() {
    let mut combo = store();
    combo.bus_mut().corrupt_readback = true;
    combo.bus_mut().fail_delete_item = true;
    let error = combo
        .write_persisted_ss_verified(&identity(), b"material")
        .err()
        .expect("cleanup fault");
    assert_eq!(error, ComboError::CleanupIncomplete);
}

#[test]
fn mismatch_cleanup_with_failing_cache_delete_is_cleanup_incomplete() {
    let mut combo = store();
    combo.bus_mut().corrupt_readback = true;
    combo.cache_mut().fail_delete_call = Some(2);
    let error = combo
        .write_persisted_ss_verified(&identity(), b"material")
        .err()
        .expect("cleanup fault");
    assert_eq!(error, ComboError::CleanupIncomplete);
}

#[test]
fn mismatch_cleanup_success_proves_absence_of_both_halves() {
    let mut combo = store();
    combo.bus_mut().corrupt_readback = true;
    let error = combo
        .write_persisted_ss_verified(&identity(), b"material")
        .err()
        .expect("readback mismatch");
    assert_eq!(error, ComboError::VerificationFailed);
    assert!(
        !combo
            .cache_mut()
            .contains(&cache::entry_description(SERVICE, ACCOUNT))
    );
    assert_eq!(combo.bus_mut().item_count(), 0);
}

#[test]
fn dh_rejects_trivial_peer_elements_one_and_prime_minus_one() {
    let prime_minus_one = {
        let mut bytes = [0xff_u8; 128];
        bytes[127] = 0x80;
        bytes.to_vec()
    };
    for bad in [vec![0x01], prime_minus_one, Vec::new(), vec![0xff; 129]] {
        let error = DhSession::negotiate(|_algorithm, _public| {
            Ok((bad.clone(), "/org/freedesktop/secrets/session/s".to_owned()))
        })
        .err()
        .expect("trivial/oversized peer element rejected");
        assert_eq!(error, SsBusError::Transport);
    }
}

#[test]
fn derived_bus_address_validator_accepts_only_the_exact_derived_form() {
    let valid = format!("unix:path={}", derived_session_bus_address());
    assert_eq!(
        validate_derived_session_bus_address(&valid)
            .expect("derived form accepted")
            .as_str(),
        derived_session_bus_address()
    );
    for invalid in [
        "tcp:host=localhost,port=0",
        "unixexec:path=/bin/false",
        "unix:abstract=/run/user/1000/bus",
        "unix:path=/run/user/1000/other-bus",
        "unix:path=relative/bus",
        "unix:path=/run/user/4294967294/bus",
        "unix:path=/run/user/1000/bus;guid=abc",
        "",
        "unix:path=/run/user/1000/bus,extra=1",
    ] {
        assert!(
            validate_derived_session_bus_address(invalid).is_err(),
            "address must be rejected: {invalid}"
        );
    }
}
