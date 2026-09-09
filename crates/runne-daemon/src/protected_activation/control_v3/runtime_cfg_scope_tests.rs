const NATIVE_TEST_GATE: &str =
    "#[cfg(all(test, target_os = \"macos\", target_arch = \"aarch64\"))]";

fn preceding_cfg<'a>(source: &'a str, consumer: &str) -> &'a str {
    let consumer_offset = source.find(consumer).expect("native consumer");
    source[..consumer_offset]
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with("#[cfg("))
        .expect("native consumer cfg")
        .trim()
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
