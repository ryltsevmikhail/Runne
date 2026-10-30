impl ProtectedBundledRuntimeProcess {
    /// Creates a transport-only owner around a real inherited-channel child.
    #[cfg(all(unix, feature = "protected-channel-integration"))]
    #[doc(hidden)]
    #[must_use]
    pub const fn test_root_transport_process(
        child: std::process::Child,
        channel: std::os::unix::net::UnixStream,
        keys: runne_api::ProtectedActivationKeys,
        owned: runne_api::ProtectedOwnedLaunchV1,
    ) -> Self {
        Self {
            child,
            #[cfg(target_os = "linux")]
            linux_launch_image: None,
            channel,
            keys,
            activation: ProtectedProcessActivation::Test { owned },
            runtime_profile: None,
            renewal_sequence: 0,
            root_control_sequence: 0,
            graceful_requested: false, graceful_acknowledged: false,
            enrollment_broker_facts: None,
            captured_stdout: None,
            captured_stderr: None,
            child_stderr: None,
        }
    }
}
