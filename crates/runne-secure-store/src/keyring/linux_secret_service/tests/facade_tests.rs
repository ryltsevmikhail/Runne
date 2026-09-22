//! Facade tests: owner binding/loss (T9), no-prompt construction (T3),
//! encrypted roundtrip, fail-closed locked/ambiguous paths.

use super::fake_bus::FakeSecretServiceBus;
use super::fake_support::{FakeProcessFacts, assert_only_allowed_and_bound, count_calls};
use crate::keyring::linux_secret_service::facade::{
    BoundSecretService, SsDeletionOutcome, SsFacadeError,
};
use crate::keyring::linux_secret_service::item_layout::EntryIdentity;
use crate::keyring::linux_secret_service::port::PeerCredentials;

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

fn bind(
    bus: FakeSecretServiceBus,
    facts: FakeProcessFacts,
) -> BoundSecretService<FakeSecretServiceBus, FakeProcessFacts> {
    BoundSecretService::bind(bus, facts).expect("owner-bound session")
}

#[test]
fn bind_and_roundtrip_through_encrypted_session() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.add_item(&entry_attributes(), b"plaintext-persisted", false);
    let mut facade = bind(bus, FakeProcessFacts::new());
    let secret = facade
        .read_entry(&identity())
        .expect("unlocked read")
        .expect("item present");
    assert_eq!(&*secret, b"plaintext-persisted");
    assert_only_allowed_and_bound(&log, ":1.42");
}

#[test]
fn missing_owner_fails_closed_before_any_service_call() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.name_owned = false;
    let error = BoundSecretService::bind(bus, FakeProcessFacts::new())
        .err()
        .expect("owner missing");
    assert_eq!(error, SsFacadeError::OwnerMissing);
    assert!(
        count_calls(&log, "OpenSession") == 0 && count_calls(&log, "SearchItems") == 0,
        "no Secret Service call may happen for a missing owner"
    );
    assert_eq!(count_calls(&log, "GetNameOwner"), 1);
}

#[test]
fn name_squat_with_invalid_executable_is_rejected() {
    let mut bus = FakeSecretServiceBus::new();
    bus.peer = PeerCredentials {
        pid: 4242,
        uid: 1000,
    };
    let mut facts = FakeProcessFacts::new();
    facts.with_peer(4242, "/home/user/.local/bin/fake-secrets", 1000, 0o755);
    let error = BoundSecretService::bind(bus, facts)
        .err()
        .expect("squat rejected");
    assert_eq!(error, SsFacadeError::OwnerInvalid);
}

#[test]
fn owner_with_wrong_uid_is_rejected() {
    let mut bus = FakeSecretServiceBus::new();
    bus.peer = PeerCredentials {
        pid: 933,
        uid: 1001,
    };
    let error = BoundSecretService::bind(bus, FakeProcessFacts::new())
        .err()
        .expect("uid mismatch rejected");
    assert_eq!(error, SsFacadeError::OwnerInvalid);
}

#[test]
fn non_root_owned_executable_is_rejected() {
    let mut bus = FakeSecretServiceBus::new();
    bus.peer = PeerCredentials {
        pid: 5151,
        uid: 1000,
    };
    let mut facts = FakeProcessFacts::new();
    facts.with_peer(5151, "/usr/bin/gnome-keyring-daemon", 1000, 0o755);
    let error = BoundSecretService::bind(bus, facts)
        .err()
        .expect("non-root owner rejected");
    assert_eq!(error, SsFacadeError::OwnerInvalid);
}

#[test]
fn world_writable_executable_is_rejected() {
    let mut bus = FakeSecretServiceBus::new();
    bus.peer = PeerCredentials {
        pid: 6161,
        uid: 1000,
    };
    let mut facts = FakeProcessFacts::new();
    facts.with_peer(6161, "/usr/bin/gnome-keyring-daemon", 0, 0o777);
    let error = BoundSecretService::bind(bus, facts)
        .err()
        .expect("world-writable rejected");
    assert_eq!(error, SsFacadeError::OwnerInvalid);
}

#[test]
fn owner_change_mid_session_fails_closed_without_new_owner_access() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.add_item(&entry_attributes(), b"secret", false);
    let mut facade = bind(bus, FakeProcessFacts::new());
    facade.bus_mut().owner_name = ":1.99".to_owned();
    let error = facade.read_entry(&identity()).expect_err("owner lost");
    assert_eq!(error, SsFacadeError::OwnerLost);
    assert_only_allowed_and_bound(&log, ":1.42");
    assert!(
        count_calls(&log, "SearchItems") == 0,
        "no service call reaches the new owner"
    );
    assert_eq!(
        count_calls(&log, "GetNameOwner"),
        2,
        "bind guard + one operation guard, then fail closed without retry"
    );
}

#[test]
fn owner_connection_death_fails_closed() {
    let bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    let mut facade = bind(bus, FakeProcessFacts::new());
    facade.bus_mut().peer_alive = false;
    let error = facade.read_entry(&identity()).expect_err("owner dead");
    assert_eq!(error, SsFacadeError::OwnerLost);
    assert_only_allowed_and_bound(&log, ":1.42");
}

#[test]
fn locked_item_fails_closed_without_prompt_or_unlock() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.add_item(&entry_attributes(), b"secret", true);
    let mut facade = bind(bus, FakeProcessFacts::new());
    let error = facade.read_entry(&identity()).expect_err("locked closed");
    assert_eq!(error, SsFacadeError::Locked);
    assert_only_allowed_and_bound(&log, ":1.42");
}

#[test]
fn locked_flip_between_search_and_read_fails_closed() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.add_item(&entry_attributes(), b"secret", false);
    let mut facade = bind(bus, FakeProcessFacts::new());
    facade.bus_mut().faults.lock_items_before_get = true;
    let error = facade.read_entry(&identity()).expect_err("race closed");
    assert_eq!(error, SsFacadeError::Unavailable);
    assert_only_allowed_and_bound(&log, ":1.42");
}

#[test]
fn absent_entry_reads_none() {
    let bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    let mut facade = bind(bus, FakeProcessFacts::new());
    assert!(facade.read_entry(&identity()).expect("no error").is_none());
    assert_only_allowed_and_bound(&log, ":1.42");
}

#[test]
fn ambiguous_matches_fail_closed() {
    let mut bus = FakeSecretServiceBus::new();
    bus.add_item(&entry_attributes(), b"one", false);
    bus.add_item(&entry_attributes(), b"two", false);
    let mut facade = bind(bus, FakeProcessFacts::new());
    let error = facade
        .read_entry(&identity())
        .expect_err("ambiguous closed");
    assert_eq!(error, SsFacadeError::Ambiguous);
}

#[test]
fn write_creates_keyring_compatible_item_then_reads_back() {
    let bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    let mut facade = bind(bus, FakeProcessFacts::new());
    facade
        .write_entry(&identity(), b"new-material")
        .expect("write");
    let read = facade
        .read_entry(&identity())
        .expect("readback")
        .expect("present");
    assert_eq!(&*read, b"new-material");
    assert_eq!(facade.bus_mut().item_count(), 1);
    assert_only_allowed_and_bound(&log, ":1.42");
}

#[test]
fn write_updates_existing_unique_item() {
    let mut bus = FakeSecretServiceBus::new();
    bus.add_item(&entry_attributes(), b"old", false);
    let mut facade = bind(bus, FakeProcessFacts::new());
    facade.write_entry(&identity(), b"rotated").expect("write");
    assert_eq!(facade.bus_mut().item_count(), 1);
    let read = facade
        .read_entry(&identity())
        .expect("readback")
        .expect("present");
    assert_eq!(&*read, b"rotated");
}

#[test]
fn write_over_locked_match_fails_closed() {
    let mut bus = FakeSecretServiceBus::new();
    bus.add_item(&entry_attributes(), b"old", true);
    let mut facade = bind(bus, FakeProcessFacts::new());
    let error = facade
        .write_entry(&identity(), b"new")
        .expect_err("locked write closed");
    assert_eq!(error, SsFacadeError::Locked);
    assert!(matches!(
        facade.read_entry(&identity()),
        Err(SsFacadeError::Locked)
    ));
}

#[test]
fn delete_removes_item_and_verifies_absence() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.add_item(&entry_attributes(), b"old", false);
    let mut facade = bind(bus, FakeProcessFacts::new());
    assert_eq!(
        facade.delete_entry(&identity()).expect("delete"),
        SsDeletionOutcome::Deleted
    );
    assert_eq!(
        facade.delete_entry(&identity()).expect("absence"),
        SsDeletionOutcome::Absent
    );
    assert!(facade.read_entry(&identity()).expect("gone").is_none());
    assert_only_allowed_and_bound(&log, ":1.42");
}
