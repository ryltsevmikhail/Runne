// Hermetic canary suite for `doctor` diagnostics redaction.
//
// Only synthetic private data is used: invented directories under a
// `tempfile::tempdir()`, invented tokens and path-like strings. The suite
// never reads host profiles and never resolves the production provider probe
// (`build_doctor_report` receives `ActiveProviderProbe::Deterministic`).
// No network is used: every synthetic profile fails to load before any
// transport would be built. Asserted surfaces: report checks, text channel,
// JSON envelope channel and the process outcome (stdout/stderr/exit code).

use super::*;

const SYNTHETIC_USER_DIR: &str = "alice-private";
const SYNTHETIC_TOKEN: &str = "sk-canary-invalid-token-0123456789abcdef";
const SYNTHETIC_PATH_LIKE: &str = "/home/alice/.secrets/profile.toml";

/// Runs the doctor pipeline hermetically and renders both output channels.
async fn doctor_channels(profile_path: &Path) -> (DiagnosticReport, String, String) {
    let report = build_doctor_report(profile_path, ActiveProviderProbe::Deterministic)
        .await
        .expect("doctor report builds for any profile state");
    let text = format_diagnostic_report(&report, OutputFormat::Text);
    let json = format_diagnostic_report(&report, OutputFormat::Json);
    let envelope =
        serde_json::to_string(&SuccessEnvelope::new(json.data_value())).expect("envelope");
    (report, text.render_text(), envelope)
}

/// Synthetic private canaries: the invented temp location, user dir, token
/// and path-like string must never reach any output channel.
fn canaries(temp: &Path) -> Vec<&str> {
    vec![
        temp.to_str().expect("utf-8 tempdir"),
        SYNTHETIC_USER_DIR,
        SYNTHETIC_TOKEN,
        SYNTHETIC_PATH_LIKE,
    ]
}

fn assert_redacted(surfaces: [(&str, &str); 2], leaked: &[&str]) {
    for (surface, payload) in surfaces {
        for canary in leaked {
            assert!(!payload.contains(canary), "{surface} disclosed canary: {canary}");
        }
    }
}

fn check_id(message: &str) -> &str {
    let start = message.rfind('[').expect("message carries a bracketed check id");
    assert!(message.ends_with(']'), "message ends with the id suffix: {message}");
    &message[start + 1..message.len() - 1]
}

fn named_check<'a>(report: &'a DiagnosticReport, name: &str) -> &'a DiagnosticCheck {
    let found = report.checks.iter().find(|check| check.name == name);
    found.unwrap_or_else(|| panic!("report carries a {name} check"))
}

fn synthetic_profile_path(temp: &Path) -> PathBuf {
    temp.join(SYNTHETIC_USER_DIR).join(".runne").join("client-profile.json")
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

#[test]
fn missing_profile_report_omits_private_location_in_both_channels() {
    let temp = tempfile::tempdir().expect("tempdir");
    let profile_path = synthetic_profile_path(temp.path());
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (report, text, json) = runtime.block_on(doctor_channels(&profile_path));

    for check in &report.checks {
        assert!(check.message.ends_with(']'), "every check carries an id: {check:?}");
    }
    let profile = named_check(&report, "Profile");
    assert_eq!(check_id(&profile.message), "profile.unavailable");
    assert!(profile.message.starts_with("Profile not found"));
    assert!(profile.details.as_deref().unwrap_or_default().contains("directory omitted"));
    // The runtime probe fails on profile load, before any transport: the
    // check must stay static and endpoint-free.
    let runtime_check = named_check(&report, "Runtime");
    assert_eq!(runtime_check.message, "Cannot connect to runtime [runtime.unreachable]");
    assert_eq!(
        runtime_check.details.as_deref(),
        Some("Runtime daemon may not be running")
    );
    let provider = named_check(&report, "Active provider");
    assert_eq!(provider.message, "none (deterministic mode) [provider.deterministic]");

    assert!(text.contains("[profile.unavailable]"));
    assert!(json.contains("[profile.unavailable]"));
    assert!(json.contains("\"overall_status\""));
    assert_redacted(
        [("text", text.as_str()), ("json", json.as_str())],
        &canaries(temp.path()),
    );
}

#[cfg(unix)]
#[test]
fn invalid_profile_content_and_location_stay_redacted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let profile_path = synthetic_profile_path(temp.path());
    std::fs::create_dir_all(profile_path.parent().expect("parent")).expect("mkdir");
    std::fs::write(
        &profile_path,
        format!("{{\"canary_token\":\"{SYNTHETIC_TOKEN}\",\"canary_hint\":\"{SYNTHETIC_PATH_LIKE}\"}}"),
    )
    .expect("write synthetic profile");
    set_file_mode(&profile_path, 0o600);

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (report, text, json) = runtime.block_on(doctor_channels(&profile_path));

    let profile = named_check(&report, "Profile");
    assert_eq!(check_id(&profile.message), "profile.invalid");
    assert!(profile.message.starts_with("Invalid or incompatible profile"));
    assert_redacted(
        [("text", text.as_str()), ("json", json.as_str())],
        // Even canaries injected into the file content must not surface.
        &canaries(temp.path()),
    );
}

#[cfg(unix)]
#[test]
fn insecure_permissions_report_names_the_cause_without_the_path() {
    let temp = tempfile::tempdir().expect("tempdir");
    let profile_path = synthetic_profile_path(temp.path());
    std::fs::create_dir_all(profile_path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&profile_path, format!("\"token\":\"{SYNTHETIC_TOKEN}\"")).expect("write");
    set_file_mode(&profile_path, 0o644);

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (report, text, json) = runtime.block_on(doctor_channels(&profile_path));

    let profile = named_check(&report, "Profile");
    assert_eq!(check_id(&profile.message), "profile.insecure_permissions");
    assert!(profile.message.starts_with("Insecure permissions"));
    assert!(profile.details.as_deref().unwrap_or_default().contains("0600"));
    assert_redacted(
        [("text", text.as_str()), ("json", json.as_str())],
        &canaries(temp.path()),
    );
}

#[test]
fn ok_profile_builder_reports_a_valid_profile_without_location() {
    let synthetic = Path::new(SYNTHETIC_PATH_LIKE).join("client-profile.json");
    let check = profile_check_ok(&synthetic);
    assert_eq!(check_id(&check.message), "profile.ok");
    assert!(check.message.starts_with("Valid and readable"));
    let details = check.details.as_deref().unwrap_or_default();
    assert!(details.contains("directory omitted"));
    assert!(!details.contains(SYNTHETIC_PATH_LIKE));
}

#[test]
fn default_profile_location_is_named_without_the_resolved_path() {
    let Ok(default) = default_local_profile_path() else {
        return; // no platform directory on this host; nothing to assert
    };
    assert_eq!(redacted_profile_location(&default), "default client profile location");
}

#[test]
fn failing_report_reaches_stdout_only_with_exit_one() {
    let temp = tempfile::tempdir().expect("tempdir");
    let profile_path = synthetic_profile_path(temp.path());
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (text_output, json_output) = runtime.block_on(async {
        let report = build_doctor_report(&profile_path, ActiveProviderProbe::Deterministic)
            .await
            .expect("report");
        (
            format_diagnostic_report(&report, OutputFormat::Text),
            // Production parity for the JSON channel: the typed output is
            // wrapped, so the envelope carries the structured `data`.
            format_diagnostic_report(&report, OutputFormat::Json),
        )
    });
    let text = process_outcome(Err(CliError::DoctorNonHealthy(text_output)), OutputFormat::Text);
    let json = process_outcome(Err(CliError::DoctorNonHealthy(json_output)), OutputFormat::Json);
    for (surface, outcome) in [("text", &text), ("json", &json)] {
        assert_eq!(outcome.exit_code, 1, "{surface} exit code");
        assert!(outcome.stderr.is_empty(), "{surface} stderr stays empty");
        for canary in canaries(temp.path()) {
            assert!(!outcome.stdout.contains(canary), "{surface} disclosed {canary}");
        }
    }
    assert!(text.stdout.contains("Some checks failed"));
    let envelope: serde_json::Value = serde_json::from_str(&json.stdout).expect("envelope");
    assert_eq!(envelope["ok"], true);
    let checks = envelope["data"]["checks"].as_array().expect("checks array");
    assert!(checks.len() >= 4, "profile, runtime, provider and credentials checks");
    for key in ["name", "status", "message", "details"] {
        assert!(checks[0].get(key).is_some(), "check keeps key {key}");
    }
}

#[test]
fn profile_error_surface_keeps_the_static_message_only() {
    let text = process_outcome(Err(CliError::Profile), OutputFormat::Text);
    assert_eq!(text.exit_code, 3);
    assert_eq!(text.stderr, "local runtime profile is unavailable\n");
    assert!(text.stdout.is_empty());

    let json = process_outcome(Err(CliError::Profile), OutputFormat::Json);
    assert_eq!(json.exit_code, 3);
    let envelope: serde_json::Value = serde_json::from_str(&json.stderr).expect("error envelope");
    assert_eq!(envelope["error"]["message"], "local runtime profile is unavailable");
    assert!(!json.stderr.contains(SYNTHETIC_PATH_LIKE));
}

#[test]
fn external_config_failures_stay_static_literals_without_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = temp.path().join("config.toml");
    std::fs::write(&config_path, "schema_version = 1\n").expect("write config");
    let probe = read_active_provider(&config_path);
    assert_eq!(
        probe,
        ActiveProviderProbe::Unavailable("external config schema version is not 2".to_owned())
    );
    let check = with_check_id(active_provider_check(&probe), active_provider_check_id(&probe));
    assert_eq!(check.message, "Cannot determine active provider [provider.unavailable]");
    assert_eq!(check.details.as_deref(), Some("external config schema version is not 2"));

    std::fs::write(&config_path, "not valid toml {{{\n").expect("write config");
    let probe = read_active_provider(&config_path);
    assert_eq!(
        probe,
        ActiveProviderProbe::Unavailable("external config is not valid TOML".to_owned())
    );
    let check = with_check_id(active_provider_check(&probe), active_provider_check_id(&probe));
    assert_eq!(check.details.as_deref(), Some("external config is not valid TOML"));
    assert!(!check.message.contains(temp.path().to_str().expect("utf-8 tempdir")));
}

#[test]
fn profile_failure_ids_stay_pairwise_distinct() {
    let synthetic = Path::new(SYNTHETIC_PATH_LIKE);
    let checks = [
        profile_check_ok(synthetic),
        profile_check_unavailable(synthetic),
        profile_check_insecure_permissions(synthetic),
        profile_check_invalid(synthetic),
        profile_check_invalid_credential(synthetic),
    ];
    let ids: Vec<&str> = checks.iter().map(|check| check_id(&check.message)).collect();
    for (index, id) in ids.iter().enumerate() {
        for other in ids.iter().skip(index + 1) {
            assert_ne!(id, other, "profile ids must stay pairwise distinct");
        }
    }
}

#[test]
fn runtime_outcome_ids_stay_pairwise_distinct() {
    let version = "0.0.0-test";
    let outcomes = [
        runtime_check_ok(version),
        runtime_check_degraded(version),
        runtime_check_unavailable(version),
        runtime_check_shutting_down(version),
        runtime_check_unknown_status(),
        runtime_check_unreachable(),
    ];
    let ids: Vec<&str> = outcomes.iter().map(|check| check_id(&check.message)).collect();
    for (index, id) in ids.iter().enumerate() {
        assert!(id.starts_with("runtime."), "runtime id namespace: {id}");
        for other in ids.iter().skip(index + 1) {
            assert_ne!(id, other, "runtime ids must stay pairwise distinct");
        }
    }
}

#[test]
fn credential_ids_cover_every_probe_variant() {
    assert_eq!(credential_check_id(CredentialProbe::Configured, false), "credential.configured");
    assert_eq!(credential_check_id(CredentialProbe::Missing, true), "credential.missing_active");
    assert_eq!(credential_check_id(CredentialProbe::Missing, false), "credential.missing");
    assert_eq!(credential_check_id(CredentialProbe::Unsupported, false), "credential.unsupported");
    assert_eq!(
        credential_check_id(CredentialProbe::AccessDenied, false),
        "credential.access_denied"
    );
    assert_eq!(
        credential_check_id(CredentialProbe::IdentityMismatch, false),
        "credential.identity_mismatch"
    );
    assert_eq!(
        credential_check_id(CredentialProbe::Unavailable, false),
        "credential.status_unavailable"
    );
}
