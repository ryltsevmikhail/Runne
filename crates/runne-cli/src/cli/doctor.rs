// Doctor command implementation - comprehensive system diagnostics.

use std::fmt::Write as _;

const DOCTOR_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Diagnostic check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warning,
    Error,
}

/// Individual diagnostic check.
#[derive(Debug, Clone)]
pub struct DiagnosticCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    pub details: Option<String>,
}

/// Complete diagnostic report.
#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    pub checks: Vec<DiagnosticCheck>,
    pub overall_status: CheckStatus,
}

impl DiagnosticReport {
    const fn new() -> Self {
        Self {
            checks: Vec::new(),
            overall_status: CheckStatus::Ok,
        }
    }

    fn add_check(&mut self, check: DiagnosticCheck) {
        match check.status {
            CheckStatus::Error => self.overall_status = CheckStatus::Error,
            CheckStatus::Warning => {
                if self.overall_status != CheckStatus::Error {
                    self.overall_status = CheckStatus::Warning;
                }
            }
            CheckStatus::Ok => {}
        }
        self.checks.push(check);
    }
}

/// Run comprehensive diagnostics.
///
/// # Errors
///
/// Returns `CliError` if critical system components fail.
async fn run_doctor(profile_path: Option<PathBuf>) -> Result<DiagnosticReport, CliError> {
    let mut report = DiagnosticReport::new();

    // Check 1: Profile existence and readability
    let profile_path = profile_path
        .or_else(|| default_local_profile_path().ok())
        .ok_or(CliError::Profile)?;

    let profile_check = match LocalRuntimeProfile::load(&profile_path) {
        Ok(_profile) => DiagnosticCheck {
            name: "Profile".to_string(),
            status: CheckStatus::Ok,
            message: "Valid and readable".to_string(),
            details: Some(format!("Path: {}", profile_path.display())),
        },
        Err(LocalProfileError::Unavailable) => DiagnosticCheck {
            name: "Profile".to_string(),
            status: CheckStatus::Error,
            message: "Profile not found".to_string(),
            details: Some(format!("Expected at: {}", profile_path.display())),
        },
        Err(LocalProfileError::InsecurePermissions) => DiagnosticCheck {
            name: "Profile".to_string(),
            status: CheckStatus::Error,
            message: "Insecure permissions".to_string(),
            details: Some(format!(
                "Profile at {} has insecure permissions (should be 0600)",
                profile_path.display()
            )),
        },
        Err(LocalProfileError::InvalidProfile) => DiagnosticCheck {
            name: "Profile".to_string(),
            status: CheckStatus::Error,
            message: "Invalid or incompatible profile".to_string(),
            details: Some(format!("Profile at {} is invalid", profile_path.display())),
        },
        Err(LocalProfileError::InvalidCredential) => DiagnosticCheck {
            name: "Profile".to_string(),
            status: CheckStatus::Error,
            message: "Invalid credential in profile".to_string(),
            details: None,
        },
    };
    report.add_check(profile_check);

    // Check 2: Runtime connectivity and health
    let health_check = match check_runtime_health(&profile_path).await {
        Ok((status, version)) => {
            let (check_status, message) = match status.as_str() {
                "ok" => (CheckStatus::Ok, "Runtime is healthy".to_string()),
                "degraded" => (
                    CheckStatus::Warning,
                    "Runtime is degraded (recovery blocked)".to_string(),
                ),
                "unavailable" => (
                    CheckStatus::Error,
                    "Runtime is unavailable (integrity blocked)".to_string(),
                ),
                "shutting_down" => (
                    CheckStatus::Warning,
                    "Runtime is shutting down".to_string(),
                ),
                _ => (CheckStatus::Error, "Unknown runtime status".to_string()),
            };
            DiagnosticCheck {
                name: "Runtime".to_string(),
                status: check_status,
                message,
                details: Some(format!("Status: {status}\nVersion: {version}")),
            }
        }
        Err(_e) => DiagnosticCheck {
            name: "Runtime".to_string(),
            status: CheckStatus::Error,
            message: "Cannot connect to runtime".to_string(),
            details: Some("Runtime daemon may not be running".to_string()),
        },
    };
    report.add_check(health_check);

    // Check 3: Active provider selection (mirrors the daemon's exact config)
    let provider_probe = probe_active_provider();
    let active_openai = matches!(&provider_probe, ActiveProviderProbe::Live(live) if live.provider == "openai");
    let active_deepseek =
        matches!(&provider_probe, ActiveProviderProbe::Live(live) if live.provider == "deepseek");
    report.add_check(active_provider_check(&provider_probe));

    // Check 4: Credential metadata per provider (no secret material)
    report.add_check(credential_check(
        ProviderCredentialId::OpenAi,
        "openai",
        active_openai,
    ));
    report.add_check(credential_check(
        ProviderCredentialId::DeepSeek,
        "deepseek",
        active_deepseek,
    ));

    Ok(report)
}

async fn check_runtime_health(profile_path: &Path) -> Result<(String, String), ()> {
    let profile = LocalRuntimeProfile::load(profile_path).map_err(|_| ())?;
    let endpoint = profile.endpoint();

    let runtime_profile =
        RuntimeProfile::validate(endpoint, "gocode-ui-client/2", GOLDEN_BUNDLE_HASH)
            .map_err(|_| ())?;

    let client = HttpRuntimeClient::new(runtime_profile, DOCTOR_HEALTH_TIMEOUT).map_err(|_| ())?;

    let health = client.probe_health().await.map_err(|_| ())?;

    let (status, version) = match health {
        RuntimeHealth::Ready { version } => ("ok".to_string(), version),
        RuntimeHealth::RecoveryBlocked { version } => ("degraded".to_string(), version),
        RuntimeHealth::IntegrityBlocked { version } => ("unavailable".to_string(), version),
        RuntimeHealth::ShuttingDown { version } => ("shutting_down".to_string(), version),
    };

    Ok((status, version))
}

/// Format diagnostic report as typed command output: the text rendering plus
/// the structured JSON payload (serialized once at render time, never
/// pre-serialized into a string).
#[must_use]
pub fn format_diagnostic_report(report: &DiagnosticReport, format: OutputFormat) -> CommandOutput {
    match format {
        OutputFormat::Text => CommandOutput::Text(format_diagnostic_text(report)),
        OutputFormat::Json => CommandOutput::Typed {
            text: format_diagnostic_text(report),
            data: diagnostic_json_data(report),
        },
    }
}

fn format_diagnostic_text(report: &DiagnosticReport) -> String {
    let mut output = String::new();

    for check in &report.checks {
        let icon = match check.status {
            CheckStatus::Ok => "✓",
            CheckStatus::Warning => "⚠",
            CheckStatus::Error => "✗",
        };

        let _ = writeln!(output, "{} {}: {}", icon, check.name, check.message);

        if let Some(details) = &check.details {
            for line in details.lines() {
                let _ = writeln!(output, "  {line}");
            }
        }
    }

    let overall_icon = match report.overall_status {
        CheckStatus::Ok => "✓",
        CheckStatus::Warning => "⚠",
        CheckStatus::Error => "✗",
    };

    let overall_message = match report.overall_status {
        CheckStatus::Ok => "All checks passed",
        CheckStatus::Warning => "Some checks have warnings",
        CheckStatus::Error => "Some checks failed",
    };

    let _ = writeln!(output, "\n{overall_icon} {overall_message}");

    output
}

fn diagnostic_json_data(report: &DiagnosticReport) -> serde_json::Value {
    let checks: Vec<serde_json::Value> = report
        .checks
        .iter()
        .map(|check| {
            serde_json::json!({
                "name": check.name,
                "status": match check.status {
                    CheckStatus::Ok => "ok",
                    CheckStatus::Warning => "warning",
                    CheckStatus::Error => "error",
                },
                "message": check.message,
                "details": check.details,
            })
        })
        .collect();

    serde_json::json!({
        "overall_status": match report.overall_status {
            CheckStatus::Ok => "ok",
            CheckStatus::Warning => "warning",
            CheckStatus::Error => "error",
        },
        "checks": checks,
    })
}
