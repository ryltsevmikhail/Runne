#[cfg(unix)]
fn qualified_pending() -> PendingFirstActivationV1 {
    let profile = ProtectedRuntimeProfileV1::new(
        runne_api::PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, 1,
        runne_runtime::bundle::BUNDLE_ID,
        hex::decode(runne_runtime::bundle::PUBLISHED_BUNDLE_HASH).unwrap().try_into().unwrap(),
        runne_http::runtime_profile::ordered_capability_digest(runne_runtime::bundle::ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES),
    ).unwrap();
    let stable = StableRuntimeBindingV1::new(
        *uuid::Uuid::now_v7().as_bytes(), "local-owner", *uuid::Uuid::now_v7().as_bytes(),
        profile.profile_id(), *profile.profile_hash(), *profile.capability_digest(),
    ).unwrap();
    PendingFirstActivationV1::new(
        *uuid::Uuid::now_v7().as_bytes(), [0x10; 32], stable,
        runne_api::ExecutableIdentityV1::new([0x40; 32], [0x50; 32], 4096).unwrap(), profile,
    ).unwrap()
}

#[cfg(unix)]
#[test]
fn qualified_existing_reopen_requires_exact_authenticated_profile() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let pending = qualified_pending();
    drop(bootstrap_protected_with_profile(
        &config, *uuid::Uuid::now_v7().as_bytes(), [0x61; 32], pending.stable(),
        Some(&pending), Some(pending.profile()), || Ok(()),
    ).unwrap());
    assert!(bootstrap_protected(
        &config, *uuid::Uuid::now_v7().as_bytes(), [0x62; 32], pending.stable(), None, || Ok(()),
    ).is_err());
    drop(bootstrap_protected_with_profile(
        &config, *uuid::Uuid::now_v7().as_bytes(), [0x63; 32], pending.stable(), None,
        Some(pending.profile()), || Ok(()),
    ).expect("qualified existing database must retain its authenticated profile"));
}

#[cfg(unix)]
#[test]
fn qualified_prepared_resume_requires_exact_authenticated_profile() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let pending = qualified_pending();
    assert!(bootstrap_protected_with_profile(
        &config, *uuid::Uuid::now_v7().as_bytes(), [0x61; 32], pending.stable(),
        Some(&pending), Some(pending.profile()),
        || Err(DaemonError::Bootstrap("injected interruption before consumption".into())),
    ).is_err());
    assert!(bootstrap_protected(
        &config, *uuid::Uuid::now_v7().as_bytes(), [0x62; 32], pending.stable(), Some(&pending), || Ok(()),
    ).is_err());
    drop(bootstrap_protected_with_profile(
        &config, *uuid::Uuid::now_v7().as_bytes(), [0x63; 32], pending.stable(), Some(&pending),
        Some(pending.profile()), || Ok(()),
    ).expect("qualified prepared database must resume with its authenticated profile"));
}
