const NATIVE_TEST_GATE: &str =
    "#[cfg(all(test, target_os = \"macos\", target_arch = \"aarch64\"))]";
const DESKTOP_PROTECTED_GATE: &str = "#[cfg(feature = \"desktop-protected\")]";
const NATIVE_OR_TEST_GATE: &str =
    "#[cfg(any(test, all(target_os = \"macos\", target_arch = \"aarch64\")))]";
const NATIVE_OR_UNIX_TEST_GATE: &str =
    "#[cfg(any(all(test, unix), all(target_os = \"macos\", target_arch = \"aarch64\")))]";
const UNIX_PROTECTED_GATE: &str =
    "#[cfg(any(test, all(unix), all(target_os = \"macos\", target_arch = \"aarch64\")))]";
const ENROLLMENT_SESSION_SCOPE_GATE: &str = "#[cfg(all(\n    feature = \"desktop-protected\",\n    any(\n        all(test, unix),\n        target_os = \"linux\",\n        all(target_os = \"macos\", target_arch = \"aarch64\")\n    )\n))]";
const ENROLLMENT_EXCHANGE_SCOPE_GATE: &str = "#[cfg(all(\n    feature = \"desktop-protected\",\n    any(target_os = \"linux\", all(target_os = \"macos\", target_arch = \"aarch64\"))\n))]";

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

    let runtime = include_str!("runtime.rs");
    for consumer in [
        "qualification_verifier:",
        "pub(crate) fn with_test_qualification(",
    ] {
        assert_eq!(preceding_cfg(runtime, consumer), NATIVE_TEST_GATE);
    }

    let control_v3 = include_str!("../control_v3.rs");
    assert_eq!(
        preceding_cfg(control_v3, "use clocks::QualificationClock;"),
        NATIVE_TEST_GATE
    );
}

#[test]
fn v3_enrollment_roots_match_native_or_test_scope() {
    let protected_activation = include_str!("../../protected_activation.rs");
    for (consumer, gate) in [
        ("mod broker_handoff;", NATIVE_OR_UNIX_TEST_GATE),
        ("pub(crate) mod control_v3;", UNIX_PROTECTED_GATE),
    ] {
        let before = source_before(protected_activation, consumer).trim_end();
        assert!(before.ends_with(gate));
    }

    let enrollment = include_str!("../../application/provider_credential_enrollment.rs");
    assert!(
        source_before(
            enrollment,
            "pub(crate) use control_facade::DaemonProtectedCredentialEnrollmentSession;"
        )
        .trim_end()
        .ends_with(ENROLLMENT_SESSION_SCOPE_GATE)
    );
    assert!(
        source_before(
            enrollment,
            "pub(crate) use control_facade::InitialCredentialExchange;"
        )
        .trim_end()
        .ends_with(ENROLLMENT_EXCHANGE_SCOPE_GATE)
    );
}
