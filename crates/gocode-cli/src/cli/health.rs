// Health check command implementation.

use gocode_runtime_client::{
    HttpRuntimeClient, RuntimeHealth, RuntimeProfile, GOLDEN_BUNDLE_HASH,
};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Health error types.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HealthError {
    ProfileUnavailable,
    ProfileIncompatible,
    ConnectionFailed,
    HealthCheckFailed,
}

impl HealthError {
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::ProfileUnavailable | Self::ProfileIncompatible => 3,
            Self::ConnectionFailed | Self::HealthCheckFailed => 1,
        }
    }
}

impl fmt::Display for HealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileUnavailable => formatter.write_str("local runtime profile is unavailable"),
            Self::ProfileIncompatible => {
                formatter.write_str("local runtime profile is incompatible")
            }
            Self::ConnectionFailed => formatter.write_str("runtime connection failed"),
            Self::HealthCheckFailed => formatter.write_str("runtime health check failed"),
        }
    }
}

/// Health status information.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HealthInfo {
    pub status: String,
    pub version: String,
    pub healthy: bool,
}

impl HealthInfo {
    fn from_runtime_health(health: &RuntimeHealth) -> Self {
        let (status, version, healthy) = match health {
            RuntimeHealth::Ready { version } => ("ok".to_owned(), version.clone(), true),
            RuntimeHealth::RecoveryBlocked { version } => {
                ("degraded".to_owned(), version.clone(), false)
            }
            RuntimeHealth::IntegrityBlocked { version } => {
                ("unavailable".to_owned(), version.clone(), false)
            }
            RuntimeHealth::ShuttingDown { version } => {
                ("shutting_down".to_owned(), version.clone(), false)
            }
        };
        Self {
            status,
            version,
            healthy,
        }
    }
}

/// Run health check against the runtime.
///
/// # Errors
///
/// Returns `HealthError` if the profile is unavailable, incompatible,
/// or the health check fails.
pub async fn run_health(profile_path: Option<PathBuf>) -> Result<HealthInfo, HealthError> {
    let profile_path = profile_path
        .or_else(|| default_local_profile_path().ok())
        .ok_or(HealthError::ProfileUnavailable)?;

    let profile = LocalRuntimeProfile::load(&profile_path).map_err(|error| match error {
        LocalProfileError::Unavailable => HealthError::ProfileUnavailable,
        LocalProfileError::InsecurePermissions | LocalProfileError::InvalidProfile => {
            HealthError::ProfileIncompatible
        }
        LocalProfileError::InvalidCredential => HealthError::ProfileIncompatible,
    })?;

    let endpoint = profile.endpoint();

    let runtime_profile = RuntimeProfile::validate(endpoint, "gocode-ui-client/2", GOLDEN_BUNDLE_HASH)
        .map_err(|_| HealthError::ProfileIncompatible)?;

    let client = HttpRuntimeClient::new(runtime_profile, HEALTH_TIMEOUT)
        .map_err(|_| HealthError::ConnectionFailed)?;

    let health = client
        .probe_health()
        .await
        .map_err(|_| HealthError::HealthCheckFailed)?;

    Ok(HealthInfo::from_runtime_health(&health))
}

fn format_health_text(info: &HealthInfo) -> String {
    if info.healthy {
        format!("ok (version {})", info.version)
    } else {
        format!("{} (version {})", info.status, info.version)
    }
}

#[must_use]
pub fn format_health(info: &HealthInfo, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => format_health_text(info),
        OutputFormat::Json => {
            let envelope = SuccessEnvelope::new(serde_json::json!({
                "status": info.status,
                "version": info.version,
                "healthy": info.healthy
            }));
            serde_json::to_string(&envelope).unwrap_or_default()
        }
    }
}
