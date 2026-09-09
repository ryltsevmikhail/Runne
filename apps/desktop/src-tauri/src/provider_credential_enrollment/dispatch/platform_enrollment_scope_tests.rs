const PLATFORM_TEST_GATE: &str =
    "#[cfg(all(test, target_os = \"macos\", target_arch = \"aarch64\"))]";

#[test]
fn platform_enrollment_fixture_consumers_match_platform_scope() {
    for (source, consumer) in [
        (
            include_str!("../../bundled_runtime_parts/enrollment.rs"),
            "pub async fn test_only_live_enrollment_runtime(",
        ),
        (
            include_str!("../../updater_status/enrollment.rs"),
            "test_revalidation: Option<runne_platform_desktop::TestOnlyEnrollmentRevalidation>,",
        ),
        (
            include_str!("../../updater_status/enrollment.rs"),
            "pub struct TestOnlyEnrollmentUpdater {",
        ),
        (
            include_str!("../../updater_status/enrollment.rs"),
            "pub async fn test_only_current_enrollment_updater(",
        ),
        (
            include_str!("../../updater_status/enrollment.rs"),
            "pub async fn test_only_expired_enrollment_updater(",
        ),
        (
            include_str!("../../updater_status/enrollment.rs"),
            "async fn test_only_enrollment_updater(",
        ),
    ] {
        let consumer_offset = source.find(consumer).expect("fixture consumer");
        let gate = source[..consumer_offset]
            .lines()
            .rev()
            .find(|line| line.trim_start().starts_with("#[cfg("))
            .expect("fixture consumer cfg")
            .trim();
        assert_eq!(gate, PLATFORM_TEST_GATE, "{consumer}");
    }
}
