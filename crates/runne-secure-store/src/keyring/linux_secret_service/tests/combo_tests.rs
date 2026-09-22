//! Combo store tests (T4 persistence fence, T5 dual-half revoke, F1′
//! dispatch reads, F4 invalidation) plus identity-bridge consistency.

use super::fake_bus::FakeSecretServiceBus;
use super::fake_cache::FakeKeyutilsCache;
use super::fake_support::{
    FakeProcessFacts, InvocationLog, assert_only_allowed_and_bound, count_calls,
};
use crate::keyring::linux_secret_service::cache::entry_description;
use crate::keyring::linux_secret_service::combo::{
    ComboError, DualHalfRevoke, LinuxComboPersistentStore, provider_identity, version_identity,
};
use crate::keyring::linux_secret_service::item_layout::EntryIdentity;
use runne_provider::CredentialVersionRef;

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

struct Fixture {
    store: LinuxComboPersistentStore<FakeSecretServiceBus, FakeProcessFacts, FakeKeyutilsCache>,
    log: InvocationLog,
}

fn fixture() -> Fixture {
    let bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    let facts = FakeProcessFacts::new();
    let cache = FakeKeyutilsCache::new();
    let store = LinuxComboPersistentStore::new(bus, facts, cache).expect("bound combo store");
    Fixture { store, log }
}

#[test]
fn ss_write_failure_rolls_back_cache_half() {
    let mut fixture = fixture();
    fixture.store.bus_mut().connect_fails = true;
    let error = fixture
        .store
        .write_persisted(&identity(), b"material")
        .err()
        .expect("combo write fails");
    assert!(matches!(error, ComboError::Ss(_)));
    assert!(!fixture.store.cache_mut().contains(&description()));
}

#[test]
fn ss_write_failure_restores_previous_cache_value() {
    let mut fixture = fixture();
    let cache = FakeKeyutilsCache::new();
    drop(cache);
    fixture.store.cache_mut().seed(&description(), b"previous");
    fixture.store.bus_mut().connect_fails = true;
    let error = fixture
        .store
        .write_persisted(&identity(), b"next")
        .err()
        .expect("combo write fails");
    assert!(matches!(error, ComboError::Ss(_)));
    assert!(fixture.store.cache_mut().contains(&description()));
}

#[test]
fn verified_write_invalidates_cache_and_requires_ss_readback() {
    let mut fixture = fixture();
    fixture
        .store
        .write_persisted_ss_verified(&identity(), b"material")
        .expect("verified write");
    assert!(!fixture.store.cache_mut().contains(&description()));
    let read = fixture
        .store
        .read_dispatch(&identity())
        .expect("dispatch read")
        .expect("present");
    assert_eq!(&*read, b"material");
    assert_eq!(fixture.store.bus_mut().item_count(), 1);
    assert_only_allowed_and_bound(&fixture.log, ":1.42");
}

#[test]
fn readback_mismatch_fails_closed_and_removes_both_halves() {
    let mut fixture = fixture();
    fixture.store.bus_mut().corrupt_readback = true;
    let error = fixture
        .store
        .write_persisted_ss_verified(&identity(), b"material")
        .err()
        .expect("readback mismatch fails");
    assert_eq!(error, ComboError::VerificationFailed);
    assert_eq!(fixture.store.bus_mut().item_count(), 0);
    assert!(!fixture.store.cache_mut().contains(&description()));
}

#[test]
fn revoke_dual_half_deletes_and_proves_absence() {
    let mut fixture = fixture();
    fixture
        .store
        .write_persisted(&identity(), b"material")
        .expect("write");
    assert_eq!(
        fixture.store.revoke_dual_half(&identity()).expect("revoke"),
        DualHalfRevoke::Revoked
    );
    assert!(!fixture.store.cache_mut().contains(&description()));
    assert!(
        fixture
            .store
            .read_dispatch(&identity())
            .expect("absent")
            .is_none()
    );
    assert_only_allowed_and_bound(&fixture.log, ":1.42");
}

#[test]
fn cache_delete_error_is_surfaced_not_swallowed() {
    let mut fixture = fixture();
    fixture
        .store
        .write_persisted(&identity(), b"material")
        .expect("write");
    fixture.store.cache_mut().fail_delete = true;
    let error = fixture
        .store
        .revoke_dual_half(&identity())
        .err()
        .expect("cache error surfaced");
    assert!(matches!(error, ComboError::Cache(_)));
}

#[test]
fn kernel_cache_lag_after_invalidate_is_incomplete_revoke() {
    let mut fixture = fixture();
    fixture
        .store
        .write_persisted(&identity(), b"material")
        .expect("write");
    fixture.store.cache_mut().stale_after_delete = true;
    let error = fixture
        .store
        .revoke_dual_half(&identity())
        .err()
        .expect("stale cache blocks completion");
    assert_eq!(error, ComboError::RevokeIncomplete);
}

#[test]
fn warm_cache_cannot_bypass_locked_store() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.add_item(&entry_attributes(), b"persisted", true);
    let cache = FakeKeyutilsCache::new();
    let mut store =
        LinuxComboPersistentStore::new(bus, FakeProcessFacts::new(), cache).expect("bound");
    let description = description();
    store.cache_mut().seed(&description, b"cached-copy");
    let error = store
        .read_dispatch(&identity())
        .err()
        .expect("locked store fails closed");
    assert!(matches!(error, ComboError::Ss(_)));
    assert_only_allowed_and_bound(&log, ":1.42");
    assert!(count_calls(&log, "SearchItems") >= 1);
}

#[test]
fn warm_cache_serves_payload_after_unlocked_probe() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.add_item(&entry_attributes(), b"persisted", false);
    let cache = FakeKeyutilsCache::new();
    let mut store =
        LinuxComboPersistentStore::new(bus, FakeProcessFacts::new(), cache).expect("bound");
    let description = description();
    store.cache_mut().seed(&description, b"cached-copy");
    let read = store
        .read_dispatch(&identity())
        .expect("warm read")
        .expect("present");
    assert_eq!(&*read, b"cached-copy");
    assert!(count_calls(&log, "SearchItems") >= 1);
    assert_eq!(count_calls(&log, "GetSecret"), 0, "payload served by cache");
}

#[test]
fn cold_cache_reads_ss_payload_without_prompt() {
    let mut bus = FakeSecretServiceBus::new();
    let log = bus.log_handle();
    bus.add_item(&entry_attributes(), b"persisted", false);
    let cache = FakeKeyutilsCache::new();
    let mut store =
        LinuxComboPersistentStore::new(bus, FakeProcessFacts::new(), cache).expect("bound");
    let read = store
        .read_dispatch(&identity())
        .expect("cold read")
        .expect("present");
    assert_eq!(&*read, b"persisted");
    assert_only_allowed_and_bound(&log, ":1.42");
}

#[test]
fn invalidate_cache_half_reports_outcomes() {
    let mut fixture = fixture();
    fixture
        .store
        .write_persisted(&identity(), b"material")
        .expect("write");
    use crate::keyring::linux_secret_service::cache::CacheDeletionOutcome;
    assert_eq!(
        fixture
            .store
            .invalidate_cache_half(&identity())
            .expect("invalidate"),
        CacheDeletionOutcome::Deleted
    );
    assert_eq!(
        fixture
            .store
            .invalidate_cache_half(&identity())
            .expect("absent"),
        CacheDeletionOutcome::Absent
    );
}

#[test]
fn identity_bridge_matches_provider_and_version_key_formats() {
    let provider = crate::provider_credential::ProviderCredentialId::DeepSeek;
    let provider_entry = provider_identity(provider);
    assert_eq!(provider_entry.service, crate::PROVIDER_CREDENTIAL_SERVICE);
    assert_eq!(provider_entry.account, provider.account());
    let provider_id = runne_provider::ProviderId::new(provider.account()).expect("provider id");
    let reference = CredentialVersionRef::new(provider_id, 3).expect("valid version reference");
    let version_entry = version_identity(&reference);
    assert!(
        version_entry
            .service
            .starts_with(crate::PROVIDER_CREDENTIAL_SERVICE)
    );
    assert!(version_entry.service.contains(".version.3."));
    assert_eq!(version_entry.account, provider.account());
    assert_eq!(
        entry_description(&version_entry.service, &version_entry.account),
        format!(
            "keyring-rs:{}@{}",
            version_entry.account, version_entry.service
        )
    );
}

fn description() -> String {
    entry_description(SERVICE, ACCOUNT)
}
