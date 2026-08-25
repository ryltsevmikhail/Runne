
#[cfg(unix)]
type ProtectedChannel = UnixStream;
#[cfg(windows)]
type ProtectedChannel = File;

/// Exact child handle, control channel, and authenticated ownership tuple for
/// one desktop-spawned bundled daemon.
pub struct ProtectedBundledRuntimeProcess {
    child: Child,
    #[cfg(windows)]
    job: OwnedHandle,
    channel: ProtectedChannel,
    keys: ProtectedActivationKeys,
    activation: ProtectedProcessActivation,
    runtime_profile: Option<ProtectedBundledRuntimeProfile>,
    renewal_sequence: u64,
    #[cfg(all(any(unix, windows), feature = "protected-channel-integration"))]
    root_control_sequence: u64,
    graceful_requested: bool,
    #[cfg(feature = "test-support")]
    captured_stdout: Option<std::process::ChildStdout>,
    #[cfg(feature = "test-support")]
    captured_stderr: Option<std::process::ChildStderr>,
}

impl fmt::Debug for ProtectedBundledRuntimeProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ProtectedBundledRuntimeProcess");
        debug.field("owned_child", &true);
        #[cfg(windows)]
        debug.field(
            "owned_job",
            &(!std::os::windows::io::AsRawHandle::as_raw_handle(&self.job).is_null()),
        );
        debug
            .field("renewal_sequence", &self.renewal_sequence)
            .field("protected_fields", &"<redacted>")
            .finish_non_exhaustive()
    }
}
