use std::fs;
use std::net::{Ipv4Addr, SocketAddr};

use gocode_runtime_client::{
    EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH, LocalProfileError, LocalRuntimeProfile,
};

fn write_profile(directory: &std::path::Path, endpoint: SocketAddr) -> std::path::PathBuf {
    let token_path = directory.join("token.bin");
    fs::write(&token_path, [0x7b; 32]).expect("write token");
    let profile_path = directory.join("client-profile.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "profileId": EXPECTED_BUNDLE_ID,
            "schemaHash": GOLDEN_BUNDLE_HASH,
            "endpoint": endpoint.to_string(),
            "tokenPath": token_path,
        }))
        .expect("profile JSON"),
    )
    .expect("write profile");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o600))
            .expect("secure profile");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("secure token");
    }
    profile_path
}

#[cfg(unix)]
#[test]
fn loads_an_exact_owner_only_local_profile_without_exposing_the_credential() {
    let directory = tempfile::tempdir().expect("temp directory");
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 43123));
    let profile_path = write_profile(directory.path(), endpoint);

    let profile = LocalRuntimeProfile::load(&profile_path).expect("load profile");

    assert_eq!(profile.endpoint().address(), endpoint);
    assert!(!format!("{profile:?}").contains("7b7b"));
}

#[cfg(unix)]
#[test]
fn rejects_non_loopback_or_unknown_profile_fields() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile_path = write_profile(
        directory.path(),
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 43123)),
    );
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("external endpoint"),
        LocalProfileError::InvalidProfile
    );

    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 43123));
    let profile_path = write_profile(directory.path(), endpoint);
    let mut profile: serde_json::Value =
        serde_json::from_slice(&fs::read(&profile_path).expect("read profile"))
            .expect("parse profile");
    profile
        .as_object_mut()
        .expect("profile object")
        .insert("unexpected".to_owned(), serde_json::json!(true));
    fs::write(
        &profile_path,
        serde_json::to_vec(&profile).expect("profile JSON"),
    )
    .expect("rewrite profile");

    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("unknown field"),
        LocalProfileError::InvalidProfile
    );
}

#[cfg(not(unix))]
#[test]
fn rejects_local_profiles_until_native_owner_acl_validation_exists() {
    let directory = tempfile::tempdir().expect("temp directory");
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 43123));
    let profile_path = write_profile(directory.path(), endpoint);

    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("unsupported ACL validation"),
        LocalProfileError::InsecurePermissions
    );
}

#[cfg(unix)]
#[test]
fn rejects_group_readable_profile_and_token_files() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temp directory");
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 43123));
    let profile_path = write_profile(directory.path(), endpoint);
    fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o640))
        .expect("weaken profile permissions");
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("insecure profile"),
        LocalProfileError::InsecurePermissions
    );

    fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o600))
        .expect("restore profile permissions");
    fs::set_permissions(
        directory.path().join("token.bin"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("weaken token permissions");
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("insecure token"),
        LocalProfileError::InsecurePermissions
    );
}
