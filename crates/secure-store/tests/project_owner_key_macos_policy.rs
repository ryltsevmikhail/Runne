#![cfg(feature = "project-owner-key-store")]

use gocode_secure_store::{
    PROJECT_OWNER_KEYCHAIN_ACCESS_GROUP, PROJECT_OWNER_KEYCHAIN_SERVICE,
    ProjectOwnerKeychainAccount, ProjectOwnerKeychainQuery, StoreStatus,
};

#[test]
fn query_specs_are_closed_and_bind_every_required_keychain_attribute() {
    for (account, account_name) in [
        (ProjectOwnerKeychainAccount::Active, "active"),
        (ProjectOwnerKeychainAccount::Pending, "pending"),
        (ProjectOwnerKeychainAccount::AnchorFloor, "anchor-floor"),
        (ProjectOwnerKeychainAccount::Recovery, "recovery"),
    ] {
        let query = ProjectOwnerKeychainQuery::new(account).expect("closed account spec");
        assert_eq!(query.service(), PROJECT_OWNER_KEYCHAIN_SERVICE);
        assert_eq!(query.account(), account_name);
        assert_eq!(query.access_group(), PROJECT_OWNER_KEYCHAIN_ACCESS_GROUP);
        assert!(query.requires_data_protection());
        assert!(query.requires_this_device_only());
        assert!(query.requires_user_presence());
        assert!(!query.is_synchronizable());
    }
    assert_eq!(
        ProjectOwnerKeychainQuery::from_account("legacy"),
        Err(StoreStatus::Denied)
    );
}

#[test]
fn fake_keychain_failures_map_closed_and_never_fall_back_to_a_legacy_acl() {
    for (status, expected) in [
        (-25_308, StoreStatus::UiUnavailable),
        (-25_293, StoreStatus::Denied),
        (-25_300, StoreStatus::Denied),
        (-1, StoreStatus::Denied),
    ] {
        assert_eq!(
            gocode_secure_store::map_project_owner_keychain_status(status),
            expected
        );
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn native_keychain_roundtrip_is_explicitly_skipped_off_macos() {
    eprintln!(
        "SKIP: native Data Protection Keychain requires macOS identity and entitlement evidence"
    );
}
