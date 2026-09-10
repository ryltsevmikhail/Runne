const LIB: &str = include_str!("../src/lib.rs");
const MACOS_IDENTITY: &str =
    include_str!("../src/updater_metadata/enrollment_tuple/macos_identity.rs");

const MACOS_ARM_TEST_SUPPORT: &str =
    "#[cfg(all(feature = \"test-support\", target_os = \"macos\", target_arch = \"aarch64\"))]";
const MACOS_TEST_SUPPORT: &str = "#[cfg(all(feature = \"test-support\", target_os = \"macos\"))]";

#[test]
fn test_support_exports_match_their_macos_only_implementations() {
    for exported_fixture in [
        "TestOnlyConnectedReadyV3EnrollmentSupervisor",
        "TestOnlyEnrollmentRevalidation",
    ] {
        let exported = LIB
            .find(exported_fixture)
            .expect("test-only fixture export must exist");
        assert_eq!(
            &LIB[..exported]
                .lines()
                .rev()
                .find(|line| line.starts_with("#[cfg("))
                .expect("fixture export must have a platform gate"),
            &MACOS_ARM_TEST_SUPPORT,
            "{exported_fixture} must not be exported when its macOS/aarch64 fixture is absent"
        );
    }

    for method in [
        "pub(super) fn local(",
        "pub(super) fn local_xpc_requirement(",
    ] {
        let offset = MACOS_IDENTITY
            .find(method)
            .expect("test-only macOS identity method must exist");
        assert_eq!(
            MACOS_IDENTITY[..offset]
                .lines()
                .rev()
                .find(|line| line.trim_start().starts_with("#[cfg("))
                .expect("method must have a platform gate")
                .trim(),
            MACOS_TEST_SUPPORT,
            "{method} must not reference the macOS XPC crate on another target"
        );
    }
}
