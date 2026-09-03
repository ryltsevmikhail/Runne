use runne_provider::{CredentialVersionRef, ProviderId};

use super::item::KEYCHAIN_ACCESS_GROUP;
use super::{
    CredentialItemLocator, CredentialKeychainStatus, KeychainBackend, map_keychain_read_status,
    map_keychain_write_status,
};

fn version(provider: &str, version: u64) -> CredentialVersionRef {
    CredentialVersionRef::new(ProviderId::new(provider).expect("provider"), version)
        .expect("version")
}

#[test]
fn locator_is_exact_dpk_generic_password_policy() {
    let reference = version("openai", 7);
    let locator = CredentialItemLocator::new(&reference);

    assert_eq!(locator.account(), "openai");
    assert_eq!(CredentialItemLocator::access_group(), KEYCHAIN_ACCESS_GROUP);
    assert_eq!(
        locator.service(),
        format!(
            "dev.runne.provider-credential.v1.version.7.{}",
            hex::encode(reference.ref_digest())
        )
    );
}

#[cfg(target_os = "macos")]
#[test]
fn exact_query_contains_required_policy_and_no_legacy_or_broad_keys() {
    let locator = CredentialItemLocator::new(&version("openai", 7));
    assert!(super::native::query_has_exact_policy(&locator));
}

#[test]
fn locator_binds_provider_version_and_digest_without_aliasing() {
    let openai_v1 = CredentialItemLocator::new(&version("openai", 1));
    let openai_v2 = CredentialItemLocator::new(&version("openai", 2));
    let deepseek_v1 = CredentialItemLocator::new(&version("deepseek", 1));

    assert_ne!(openai_v1.service(), openai_v2.service());
    assert_ne!(openai_v1.service(), deepseek_v1.service());
    assert_ne!(openai_v1.account(), deepseek_v1.account());
}

#[test]
fn locked_and_no_login_statuses_are_typed_unavailable() {
    for status in [-25_308, -25_291] {
        assert_eq!(
            map_keychain_read_status(status),
            CredentialKeychainStatus::Unavailable
        );
        assert_eq!(
            map_keychain_write_status(status),
            CredentialKeychainStatus::Unavailable
        );
    }
}

#[test]
fn duplicate_and_missing_are_closed_and_distinct() {
    assert_eq!(
        map_keychain_write_status(-25_299),
        CredentialKeychainStatus::Duplicate
    );
    assert_eq!(
        map_keychain_read_status(-25_300),
        CredentialKeychainStatus::Absent
    );
    assert_eq!(
        map_keychain_write_status(-25_300),
        CredentialKeychainStatus::Absent
    );
    assert_eq!(
        map_keychain_write_status(-34_018),
        CredentialKeychainStatus::AccessDenied
    );
    assert_eq!(
        map_keychain_read_status(-34_018),
        CredentialKeychainStatus::AccessDenied
    );
    assert_eq!(
        map_keychain_read_status(-1),
        CredentialKeychainStatus::Uncertain
    );
    assert_eq!(
        super::map_keychain_read_result(0, false),
        CredentialKeychainStatus::Unavailable
    );
}

#[cfg(target_os = "macos")]
#[test]
fn native_access_group_denies_unsigned_or_completes_same_process_round_trip() {
    use runne_credential_service_core::CredentialBackendResult;
    use runne_provider::CredentialMaterial;

    let reference = version("runne-task7-native", 1);
    let locator = CredentialItemLocator::new(&reference);
    let material = CredentialMaterial::from_bytes(b"not-a-real-provider-secret".to_vec())
        .expect("bounded material");
    let stored = KeychainBackend::store(&reference, material);
    if stored == CredentialBackendResult::AccessDenied {
        assert_ne!(
            std::env::var("RUNNE_SIGNED_KEYCHAIN_TEST").as_deref(),
            Ok("1"),
            "signed qualification lacks the service-only access group"
        );
        return;
    }
    assert_eq!(stored, CredentialBackendResult::Observed(()));
    assert_eq!(
        super::native::read(&locator).expect("readback"),
        b"not-a-real-provider-secret"
    );
    assert_eq!(
        super::native::add(&locator, b"replacement-is-forbidden"),
        CredentialKeychainStatus::Duplicate
    );
    assert_eq!(
        super::native::read(&CredentialItemLocator::new(&reference))
            .expect("reconstructed locator read"),
        b"not-a-real-provider-secret"
    );
    assert_eq!(
        super::native::read(&CredentialItemLocator::with_account_for_test(
            &reference,
            "wrong-provider"
        )),
        Err(CredentialKeychainStatus::Absent)
    );
    assert_eq!(
        KeychainBackend::delete(&reference),
        CredentialBackendResult::Observed(())
    );
    assert_eq!(
        super::native::read(&locator),
        Err(CredentialKeychainStatus::Absent)
    );
}
