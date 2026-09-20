// Doctor command implementation - comprehensive system diagnostics.
//
// Redaction invariant: no local path, raw profile/config content or raw
// transport error enters any check `message` or `details`. Profile locations
// are reduced by `doctor_redaction.rs`; check ids stay distinguishable via
// stable bracketed suffixes in `message`.

use std::fmt::Write as _;

const DOCTOR_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

include!("doctor_redaction.rs");

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
    let profile_path = profile_path
        .or_else(|| default_local_profile_path().ok())
        .ok_or(CliError::Profile)?;
    build_doctor_report(&profile_path, probe_active_provider()).await
}

/// Builds the doctor report for an explicit profile location and provider
/// probe. Tests pass synthetic inputs (`ActiveProviderProbe::Deterministic`)
/// so no host external config is read.
///
/// # Errors
///
/// Currently infallible for any profile state; the `Result` keeps the
/// production call shape (`CliError::Profile` is raised by `run_doctor`
/// when no profile location can be resolved at all).
async fn build_doctor_report(
    profile_path: &Path,
    provider_probe: ActiveProviderProbe,
) -> Result<DiagnosticReport, CliError> {
    let mut report = DiagnosticReport::new();

    // Check 1: Profile existence and readability (location redacted on every
    // branch; the typed error variant preserves the failure cause)
    let profile_check = match LocalRuntimeProfile::load(profile_path) {
        Ok(_profile) => profile_check_ok(profile_path),
        Err(LocalProfileError::Unavailable) => profile_check_unavailable(profile_path),
        Err(LocalProfileError::InsecurePermissions) => {
            profile_check_insecure_permissions(profile_path)
        }
        Err(LocalProfileError::InvalidProfile) => profile_check_invalid(profile_path),
        Err(LocalProfileError::InvalidCredential) => profile_check_invalid_credential(profile_path),
    };
    report.add_check(profile_check);

    // Check 2: Runtime connectivity and health (raw errors never rendered)
    let health_check = match check_runtime_health(profile_path).await {
        Ok((status, version)) => match status.as_str() {
            "ok" => runtime_check_ok(&version),
            "degraded" => runtime_check_degraded(&version),
            "unavailable" => runtime_check_unavailable(&version),
            "shutting_down" => runtime_check_shutting_down(&version),
            _ => runtime_check_unknown_status(),
        },
        Err(_e) => runtime_check_unreachable(),
    };
    report.add_check(health_check);

    // Check 3: Active provider selection (mirrors the daemon's exact config)
    let active_openai = matches!(&provider_probe, ActiveProviderProbe::Live(live) if live.provider == "openai");
    let active_deepseek =
        matches!(&provider_probe, ActiveProviderProbe::Live(live) if live.provider == "deepseek");
    report.add_check(with_check_id(
        active_provider_check(&provider_probe),
        active_provider_check_id(&provider_probe),
    ));

    // Check 4: Credential metadata per provider (no secret material)
    report.add_check(credentialed_check(
        ProviderCredentialId::OpenAi,
        "openai",
        active_openai,
    ));
    report.add_check(credentialed_check(
        ProviderCredentialId::DeepSeek,
        "deepseek",
        active_deepseek,
    ));

    Ok(report)
}

/// One credential check tagged with its stable id. The store is probed
/// exactly once: the message and the bracketed id derive from the same
/// observation, so they cannot disagree even if the store state changes
/// afterwards.
fn credentialed_check(id: ProviderCredentialId, provider: &str, active: bool) -> DiagnosticCheck {
    let probe = probe_credential(id);
    with_check_id(
        credential_check_from_probe(probe, provider, active),
        credential_check_id(probe, active),
    )
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

#[cfg(test)]
#[path = "doctor_redaction_tests.rs"]
mod doctor_redaction_tests;

#[cfg(test)]
#[path = "doctor_redaction_version_tests.rs"]
mod doctor_redaction_version_tests;

#[cfg(test)]
#[path = "doctor_redaction_canary_tests.rs"]
mod doctor_redaction_canary_tests;

#[cfg(test)]
#[path = "doctor_credential_builder_tests.rs"]
mod doctor_credential_builder_tests;
