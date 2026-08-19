// Status command implementation.

use std::path::Path;

/// Trait for runtime connection, enabling mock-based tests.
pub trait StatusConnector {
    /// Connects to the runtime and returns status information.
    ///
    /// # Errors
    ///
    /// Returns `StatusError` if the profile is unavailable, incompatible,
    /// or the connection fails.
    fn connect(&self, profile_path: &Path) -> Result<StatusInfo, StatusError>;
}

/// Status information returned on successful connection.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StatusInfo {
    pub principal: String,
    pub generation: u64,
    pub daemon_instance_id: String,
}

/// Status error types.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StatusError {
    ProfileUnavailable,
    ProfileIncompatible,
    ConnectionFailed,
}

impl StatusError {
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::ProfileUnavailable | Self::ProfileIncompatible => 3,
            Self::ConnectionFailed => 1,
        }
    }
}

impl fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileUnavailable => formatter.write_str("local runtime profile is unavailable"),
            Self::ProfileIncompatible => formatter.write_str("local runtime profile is incompatible"),
            Self::ConnectionFailed => formatter.write_str("runtime connection failed"),
        }
    }
}

/// Native status connector using real runne-runtime-client.
pub struct NativeStatusConnector;

impl StatusConnector for NativeStatusConnector {
    fn connect(&self, _profile_path: &Path) -> Result<StatusInfo, StatusError> {
        // Synchronous placeholder - actual async implementation below
        Err(StatusError::ConnectionFailed)
    }
}

/// Async status check using the real runtime profile.
///
/// # Errors
///
/// Returns `StatusError` if the profile is unavailable, incompatible,
/// or the connection fails.
pub async fn run_status_async(profile_path: PathBuf) -> Result<String, StatusError> {
    let profile = LocalRuntimeProfile::load(&profile_path).map_err(|error| match error {
        LocalProfileError::Unavailable => StatusError::ProfileUnavailable,
        LocalProfileError::InsecurePermissions | LocalProfileError::InvalidProfile => {
            StatusError::ProfileIncompatible
        }
        LocalProfileError::InvalidCredential => StatusError::ProfileIncompatible,
    })?;

    let client = profile
        .connect(std::time::Duration::from_secs(30))
        .await
        .map_err(|_| StatusError::ConnectionFailed)?;

    let session_info = client.session_info();
    let status = StatusInfo {
        principal: session_info.principal_id.clone(),
        generation: session_info.launch_generation,
        daemon_instance_id: session_info.daemon_instance_id.clone(),
    };

    let provider_lines = format_status_lines(&probe_active_provider());
    Ok(format!("{}\n{provider_lines}", format_status(&status)))
}

fn format_status(status: &StatusInfo) -> String {
    format!(
        "connected\nprincipal: {}\ngeneration: {}\ndaemon: {}",
        status.principal, status.generation, status.daemon_instance_id
    )
}
