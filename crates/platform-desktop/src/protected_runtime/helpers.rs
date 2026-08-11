
/// Exact child handle, control channel, and authenticated ownership tuple for
/// one desktop-spawned bundled daemon.
pub struct ProtectedBundledRuntimeProcess {
    #[cfg(unix)]
    child: Child,
    #[cfg(unix)]
    channel: UnixStream,
    #[cfg(unix)]
    keys: ProtectedActivationKeys,
    #[cfg(unix)]
    activation: ProtectedProcessActivation,
    runtime_profile: Option<ProtectedBundledRuntimeProfile>,
    renewal_sequence: u64,
    root_control_sequence: u64,
    graceful_requested: bool,
    #[cfg(feature = "test-support")]
    captured_stdout: Option<std::process::ChildStdout>,
    #[cfg(feature = "test-support")]
    captured_stderr: Option<std::process::ChildStderr>,
}

impl fmt::Debug for ProtectedBundledRuntimeProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBundledRuntimeProcess")
            .field("owned_child", &true)
            .field("renewal_sequence", &self.renewal_sequence)
            .field("protected_fields", &"<redacted>")
            .finish_non_exhaustive()
    }
}
