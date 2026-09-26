pub(crate) fn record(stage: &'static str, succeeded: bool) {
    #[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
    {
        runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage_outcome(
            stage, succeeded,
        );
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-native-enrollment-qualification")))]
    let _ = (stage, succeeded);
}
