// Health check command implementation.

use runne_runtime_client::{
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

/// Typed health output: the text rendering plus the structured JSON payload
/// (serialized once at render time, never pre-serialized into a string).
#[must_use]
pub fn format_health(info: &HealthInfo) -> CommandOutput {
    CommandOutput::typed(
        format_health_text(info),
        serde_json::json!({
            "status": info.status,
            "version": info.version,
            "healthy": info.healthy
        }),
    )
}

fn health_command_output(info: &HealthInfo) -> Result<CommandOutput, CliError> {
    let output = format_health(info);
    if info.healthy {
        Ok(output)
    } else {
        Err(CliError::HealthNonHealthy(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(version: &str, status: &str) -> HealthInfo {
        match status {
            "ok" => HealthInfo::from_runtime_health(&RuntimeHealth::Ready {
                version: version.to_owned(),
            }),
            "degraded" => HealthInfo::from_runtime_health(&RuntimeHealth::RecoveryBlocked {
                version: version.to_owned(),
            }),
            "unavailable" => HealthInfo::from_runtime_health(&RuntimeHealth::IntegrityBlocked {
                version: version.to_owned(),
            }),
            "shutting_down" => HealthInfo::from_runtime_health(&RuntimeHealth::ShuttingDown {
                version: version.to_owned(),
            }),
            _ => unreachable!(),
        }
    }

    #[test]
    fn health_text_exit_code_fails_closed_for_every_runtime_state() {
        for (status, expected_code) in [
            ("ok", 0),
            ("degraded", 1),
            ("unavailable", 1),
            ("shutting_down", 1),
        ] {
            let outcome = process_outcome(
                health_command_output(&health("1.2.3", status)),
                OutputFormat::Text,
            );
            assert_eq!(outcome.exit_code, expected_code, "{status}");
            assert_eq!(outcome.stderr, "", "{status}");
            assert_eq!(outcome.stdout, format!("{status} (version 1.2.3)\n"));
        }
    }

    #[test]
    fn health_json_renders_typed_data_once_for_ok_and_nonhealthy_states() {
        for (status, expected_code) in [
            ("ok", 0),
            ("degraded", 1),
            ("unavailable", 1),
            ("shutting_down", 1),
        ] {
            let outcome = process_outcome(
                health_command_output(&health("1.2.3", status)),
                OutputFormat::Json,
            );
            assert_eq!(outcome.exit_code, expected_code, "{status}");
            assert_eq!(outcome.stderr, "", "{status}");
            let envelope: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
            assert_eq!(envelope["ok"], true, "{status}");
            assert!(
                envelope["data"].get("output").is_none(),
                "{status}: stringly data.output payload is forbidden"
            );
            assert_eq!(envelope["data"]["status"], status, "{status}");
            assert_eq!(envelope["data"]["healthy"], status == "ok", "{status}");
            assert_eq!(envelope["data"]["version"], "1.2.3", "{status}");
        }
    }
}
