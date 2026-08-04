/// Closed renderer-safe runtime connection disposition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAvailability {
    #[default]
    Unconfigured,
    ProfileLoaded,
    PeerVerified,
    BootstrapProved,
    Authenticated,
    Reconciling,
    Live,
    Reconnecting,
    Incompatible,
    Revoked,
    ResyncRequired,
    Fatal,
}

/// Closed host-owned runtime launch mode exposed to the renderer without
/// connection details.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    #[default]
    ExternalLocal,
    Bundled,
}

impl RuntimeMode {
    pub const ALL: [Self; 2] = [Self::ExternalLocal, Self::Bundled];
}

/// Renderer-safe lifecycle of the native host's selected runtime mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLifecycleStatus {
    ConfigurationRequired,
    Starting,
    Ready,
    Restarting,
    Degraded,
    Failed,
    External,
}

impl RuntimeLifecycleStatus {
    pub const ALL: [Self; 7] = [
        Self::ConfigurationRequired,
        Self::Starting,
        Self::Ready,
        Self::Restarting,
        Self::Degraded,
        Self::Failed,
        Self::External,
    ];
}

/// Closed renderer-safe reason for a host-owned bundled activation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFailureCode {
    ConfigurationRequired,
    ProtectedActivationUnavailable,
    BundledExecutableUnavailable,
    BundledExecutableIdentityMismatch,
    ProtectedReadinessRejected,
    BundledRestartExhausted,
    BundledShutdownIncomplete,
    UnsupportedPlatformBackend,
    DowngradedExternalProfile,
}

impl RuntimeFailureCode {
    pub const ALL: [Self; 9] = [
        Self::ConfigurationRequired,
        Self::ProtectedActivationUnavailable,
        Self::BundledExecutableUnavailable,
        Self::BundledExecutableIdentityMismatch,
        Self::ProtectedReadinessRejected,
        Self::BundledRestartExhausted,
        Self::BundledShutdownIncomplete,
        Self::UnsupportedPlatformBackend,
        Self::DowngradedExternalProfile,
    ];
}

/// Opaque native-host lease for exactly one bundled client installation.
///
/// The value is deliberately neither serializable nor constructible outside
/// `AppCore`. Every start, restart, failure, and successful installation
/// rotates the current lease.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BundledRuntimeActivationLease {
    epoch: u64,
}

impl std::fmt::Debug for BundledRuntimeActivationLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BundledRuntimeActivationLease")
            .field("epoch", &"<opaque>")
            .finish()
    }
}

/// Invalid success-path runtime transition.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("runtime connection transition is invalid")]
pub struct RuntimeTransitionError;

impl RuntimeAvailability {
    pub const ALL: [Self; 12] = [
        Self::Unconfigured,
        Self::ProfileLoaded,
        Self::PeerVerified,
        Self::BootstrapProved,
        Self::Authenticated,
        Self::Reconciling,
        Self::Live,
        Self::Reconnecting,
        Self::Incompatible,
        Self::Revoked,
        Self::ResyncRequired,
        Self::Fatal,
    ];

    #[must_use]
    pub const fn allows_mutations(self) -> bool {
        matches!(self, Self::Live)
    }

    /// Applies one allowed closed state transition.
    ///
    /// # Errors
    ///
    /// Returns an error when peer, bootstrap or authentication proof would be
    /// skipped.
    pub const fn transition_to(self, next: Self) -> Result<Self, RuntimeTransitionError> {
        if matches!(
            (self, next),
            (Self::Unconfigured | Self::Reconnecting, Self::ProfileLoaded)
                | (Self::ProfileLoaded, Self::PeerVerified)
                | (Self::PeerVerified, Self::BootstrapProved)
                | (Self::BootstrapProved, Self::Authenticated)
                | (
                    Self::Authenticated | Self::Live | Self::Reconnecting | Self::ResyncRequired,
                    Self::Reconciling
                )
                | (Self::Reconciling, Self::Live)
                | (
                    Self::ProfileLoaded
                        | Self::PeerVerified
                        | Self::BootstrapProved
                        | Self::Authenticated
                        | Self::Reconciling
                        | Self::Live,
                    Self::Reconnecting
                        | Self::Incompatible
                        | Self::Revoked
                        | Self::ResyncRequired
                        | Self::Fatal
                )
        ) {
            Ok(next)
        } else {
            Err(RuntimeTransitionError)
        }
    }
}
