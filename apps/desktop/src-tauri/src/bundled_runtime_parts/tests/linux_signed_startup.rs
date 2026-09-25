#[test]
fn linux_signed_tuple_on_v2_renewal_transitions_and_v3_renewal_verifies() {
    assert_eq!(
        linux_signed_startup::route(true, false, false, false),
        Route::Transition,
        "new signed evidence upgrades a baseline V2 renewal"
    );
    assert_eq!(
        linux_signed_startup::route(true, true, true, true),
        Route::VerifyV3,
        "an active V3 renewal retains and verifies its marker"
    );
    assert_eq!(
        linux_signed_startup::route(false, true, true, true),
        Route::RejectDowngrade
    );
    assert_eq!(
        linux_signed_startup::route(false, false, false, false),
        Route::Baseline,
        "unsigned V2 remains allowed before enrollment"
    );
    assert_eq!(
        linux_signed_startup::route(true, true, true, false),
        Route::RejectDowngrade,
        "V3 profile without its retained marker must fail closed"
    );
    assert_eq!(
        linux_signed_startup::route(true, false, false, true),
        Route::Transition,
        "a stale marker cannot classify an actual V2 profile as V3"
    );
}

#[test]
fn linux_signed_v3_latch_survives_controller_recreation_and_fails_closed() {
    let directory = tempfile::tempdir().expect("private runtime root");
    let runtime_root = directory.path().join("bundled-runtime");
    std::fs::create_dir(&runtime_root).expect("runtime root");
    let path = super::linux_v3_latch::state_path(&runtime_root).expect("durable latch path");

    assert!(!super::linux_v3_latch::load(&path).expect("initial absence"));
    super::linux_v3_latch::persist(&path).expect("persist active V3 proof");
    assert!(super::linux_v3_latch::load(&path).expect("reloaded V3 proof"));
    std::fs::remove_dir(&runtime_root).expect("runtime reset");
    std::fs::create_dir(&runtime_root).expect("runtime root recreated");
    assert!(super::linux_v3_latch::load(&path).expect("latch survives runtime reset"));

    std::fs::write(&path, b"corrupt").expect("corrupt latch fixture");
    assert!(super::linux_v3_latch::load(&path).is_err());
}

#[test]
fn linux_restart_policy_uses_durable_latch_to_reject_missing_signed_tuple() {
    let directory = tempfile::tempdir().expect("private profile");
    let runtime_root = directory.path().join("bundled-runtime");
    std::fs::create_dir(&runtime_root).expect("runtime root");
    let path = super::linux_v3_latch::state_path(&runtime_root).expect("latch path");

    let was_v3_active = super::linux_v3_latch::load(&path).expect("initial latch state");
    assert_eq!(
        linux_signed_startup::route(false, was_v3_active, false, false),
        Route::Baseline
    );
    super::linux_v3_latch::persist(&path).expect("persist V3 latch");
    let was_v3_active = super::linux_v3_latch::load(&path).expect("reloaded latch");
    assert_eq!(
        linux_signed_startup::route(false, was_v3_active, false, false),
        Route::RejectDowngrade
    );
    assert_eq!(
        linux_signed_startup::route(true, was_v3_active, false, false),
        Route::Transition
    );
}
