const NATIVE_TEST_GATE: &str =
    "#[cfg(all(test, target_os = \"macos\", target_arch = \"aarch64\"))]";
const DESKTOP_PROTECTED_GATE: &str = "#[cfg(feature = \"desktop-protected\")]";
fn preceding_cfg<'a>(source: &'a str, consumer: &str) -> &'a str {
    let consumer_offset = source.find(consumer).expect("native consumer");
    source[..consumer_offset]
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with("#[cfg("))
        .expect("native consumer cfg")
        .trim()
}

fn source_before<'a>(source: &'a str, consumer: &str) -> &'a str {
    let consumer_offset = source.find(consumer).expect("native consumer");
    &source[..consumer_offset]
}

#[test]
fn qualification_test_support_matches_native_platform_scope() {
    let initial_exchange = include_str!("initial_exchange.rs");
    for consumer in [
        "mod qualification_admission_tests;",
        "pub(crate) mod session_test_support;",
        "pub(crate) fn verify_and_retain_qualification_admission_for_test(",
    ] {
        assert_eq!(preceding_cfg(initial_exchange, consumer), NATIVE_TEST_GATE);
    }

    // The V3 dispatch struct (with its test-support fields) lives in its own
    // included file since the 300-line source split.
    let dispatch = include_str!("runtime/dispatch.rs");
    for consumer in [
        "qualification_verifier:",
        "pub(crate) fn with_test_qualification(",
    ] {
        assert_eq!(preceding_cfg(dispatch, consumer), NATIVE_TEST_GATE);
    }

    let control_v3 = include_str!("../control_v3.rs");
    assert_eq!(
        preceding_cfg(control_v3, "use clocks::QualificationClock;"),
        NATIVE_TEST_GATE
    );
}

const NATIVE_MACOS_GATE: &str = "#[cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))]";

#[test]
fn v3_enrollment_roots_match_native_or_test_scope() {
    // The Linux local enrollment does not mount the broker handoff or the
    // credential-enrollment session: those stay native-macOS scope, and the
    // unix-test widening has no remaining consumers on this tree.
    let protected_activation = include_str!("../../protected_activation.rs");
    let before = source_before(protected_activation, "mod broker_handoff;").trim_end();
    assert!(before.ends_with(NATIVE_MACOS_GATE));
    assert!(
        before[..before.len() - NATIVE_MACOS_GATE.len()]
            .trim_end()
            .ends_with(DESKTOP_PROTECTED_GATE)
    );
    // The Linux enrollment mounts the V3 loop for production on unix, and
    // the shared transcript stays compiled for the windows V3 entry too.
    assert_eq!(
        preceding_cfg(protected_activation, "pub(crate) mod control_v3;"),
        "#[cfg(all(any(unix, windows), feature = \"desktop-protected\"))]"
    );

    let enrollment = include_str!("../../application/provider_credential_enrollment.rs");
    assert!(
        source_before(
            enrollment,
            "pub(crate) use control_facade::DaemonProtectedCredentialEnrollmentSession;"
        )
        .trim_end()
        .ends_with("target_arch = \"aarch64\"\n))]")
    );
}
