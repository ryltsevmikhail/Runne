
impl Drop for ProtectedBundledRuntimeProcess {
    fn drop(&mut self) {
        #[cfg(any(unix, windows))]
        {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

/// Bounded supervisor for the concrete protected bundled-runtime path.
pub struct ProtectedBundledRuntimeSupervisor {
    launcher: DevelopmentBundledRuntimeLauncher,
    spec: ProtectedBundledRuntimeLaunchSpec,
    process: Option<ProtectedBundledRuntimeProcess>,
    pending_profile: Option<ProtectedBundledRuntimeProfile>,
    backoff: BundledRuntimeBackoff,
    restart_at: Option<Instant>,
    state: BundledRuntimeLifecycleState,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    credential_service_rejoin:
        Option<credential_service_session::CredentialServiceRejoinContext>,
}

impl fmt::Debug for ProtectedBundledRuntimeSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBundledRuntimeSupervisor")
            .field("state", &self.state)
            .field("owned_process", &self.process.is_some())
            .field("pending_profile", &self.pending_profile.is_some())
            .finish_non_exhaustive()
    }
}
