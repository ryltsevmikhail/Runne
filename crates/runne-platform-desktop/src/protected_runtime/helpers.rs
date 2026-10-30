
#[cfg(unix)]
type ProtectedChannel = UnixStream;
#[cfg(windows)]
type ProtectedChannel = File;

/// Daemon-committed rendezvous facts from one verified enrollment prelude.
#[derive(Clone, Copy)]
#[cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
pub struct EnrollmentBrokerFacts {
    terminal_session: Option<[u8; 16]>,
    binding: [u8; 32],
    publication_public_key: [u8; 32],
}

#[cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
impl EnrollmentBrokerFacts {
    pub const fn new(binding: [u8; 32], publication_public_key: [u8; 32]) -> Self {
        Self {
            terminal_session: None,
            binding,
            publication_public_key,
        }
    }

    #[must_use] pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    #[must_use] pub const fn publication_public_key(&self) -> [u8; 32] {
        self.publication_public_key
    }
}

/// Exact child handle, control channel, and authenticated ownership tuple for
/// one desktop-spawned bundled daemon.
pub struct ProtectedBundledRuntimeProcess {
    child: Child,
    #[cfg(unix)]
    child_stderr: Option<ProtectedChildStderr>,
    #[cfg(target_os = "linux")]
    linux_launch_image: Option<LinuxLaunchImage>,
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
    graceful_acknowledged: bool,
    /// Rendezvous facts retained from the verified enrollment prelude; only a
    /// same-process V2→V3 transition carries them. Absent facts fail closed.
    #[cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
    enrollment_broker_facts: Option<EnrollmentBrokerFacts>,
    #[cfg(feature = "test-support")]
    captured_stdout: Option<std::process::ChildStdout>,
    #[cfg(feature = "test-support")]
    captured_stderr: Option<std::process::ChildStderr>,
}

#[cfg(target_os = "linux")]
struct LinuxLaunchImage {
    runtime_root: PathBuf,
    executable: File,
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
