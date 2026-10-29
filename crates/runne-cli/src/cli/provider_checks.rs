// Doctor check builders and `status` provider lines built on the metadata-only
// probes from `provider_readiness.rs`. No secret material enters any output.
//
// Shared namespace note: `include!`-composed into `main.rs`; `DiagnosticCheck`
// and `CheckStatus` come from `doctor.rs`, all probe types from
// `provider_readiness.rs` — no re-imports here.

/// Formats `status` lines for the active provider selection.
#[must_use]
pub fn format_status_lines(probe: &ActiveProviderProbe) -> String {
    match probe {
        ActiveProviderProbe::Deterministic => "provider: none (deterministic_v1)".to_owned(),
        ActiveProviderProbe::Live(live) => {
            let credential = probe_credential(credential_id_for(live.provider));
            format!(
                "provider: {} ({})\nmodel: {} (profile {})\ncredential: {} (source: {})",
                live.provider,
                live.mode,
                live.model_id,
                live.profile_id,
                credential.as_str(),
                credential_source()
            )
        }
        ActiveProviderProbe::Unavailable(message) => {
            format!("provider: unavailable ({message})")
        }
    }
}

/// Builds the doctor check for the active provider selection.
#[must_use]
pub fn active_provider_check(probe: &ActiveProviderProbe) -> DiagnosticCheck {
    match probe {
        ActiveProviderProbe::Deterministic => DiagnosticCheck {
            name: "Active provider".to_string(),
            status: CheckStatus::Ok,
            message: "none (deterministic mode)".to_string(),
            details: Some(
                "No live provider selected; credential-free deterministic runtime".to_string(),
            ),
        },
        ActiveProviderProbe::Live(live) => DiagnosticCheck {
            name: "Active provider".to_string(),
            status: CheckStatus::Ok,
            message: format!("{} ({})", live.provider, live.mode),
            details: Some(format!(
                "Model: {} (revision {})\nProfile: {}",
                live.model_id, live.model_revision, live.profile_id
            )),
        },
        ActiveProviderProbe::Unavailable(message) => DiagnosticCheck {
            name: "Active provider".to_string(),
            status: CheckStatus::Warning,
            message: "Cannot determine active provider".to_string(),
            details: Some(message.clone()),
        },
    }
}

/// Builds the doctor check for one provider credential (metadata only) from
/// an already-taken probe.
///
/// Callers must probe the store exactly once and derive both this check and
/// its stable id (`credential_check_id`) from that single observation, so the
/// message and the id cannot disagree.
#[must_use]
pub fn credential_check_from_probe(
    probe: CredentialProbe,
    provider: &str,
    active: bool,
) -> DiagnosticCheck {
    let (status, message) = match probe {
        CredentialProbe::Configured => {
            (CheckStatus::Ok, format!("{provider} credential configured"))
        }
        CredentialProbe::Missing if active => (
            CheckStatus::Error,
            format!("{provider} credential missing (active provider)"),
        ),
        CredentialProbe::Missing => (
            CheckStatus::Warning,
            format!("{provider} credential not configured"),
        ),
        CredentialProbe::Unsupported => (
            CheckStatus::Warning,
            "credential storage not supported on this platform".to_string(),
        ),
        CredentialProbe::AccessDenied => (
            CheckStatus::Error,
            format!("{provider} credential access denied"),
        ),
        CredentialProbe::IdentityMismatch => (
            CheckStatus::Error,
            format!("{provider} credential identity mismatch"),
        ),
        CredentialProbe::Unavailable => (
            CheckStatus::Warning,
            format!("cannot check {provider} credential status"),
        ),
    };
    let details = match probe {
        CredentialProbe::Missing | CredentialProbe::AccessDenied => format!(
            "Credential enrollment requires the authenticated provider-credential broker.\nSource: {}",
            credential_source()
        ),
        _ => format!("Source: {}", credential_source()),
    };
    DiagnosticCheck {
        name: format!("Credential ({provider})"),
        status,
        message,
        details: Some(details),
    }
}

#[cfg(test)]
mod provider_checks_tests {
    use super::*;

    #[test]
    fn active_provider_probe_reports_deterministic_when_config_missing() {
        let config_path = std::env::temp_dir().join("runne-provider-readiness-missing-config.toml");
        let _ = std::fs::remove_file(&config_path);
        assert_eq!(
            read_active_provider(&config_path),
            ActiveProviderProbe::Deterministic
        );
    }

    #[test]
    fn active_provider_probe_rejects_unknown_keys_and_schema_versions() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(&config_path, "schema_version = 2\nunknown_key = true\n").unwrap();
        assert!(matches!(
            read_active_provider(&config_path),
            ActiveProviderProbe::Unavailable(_)
        ));
        std::fs::write(&config_path, "schema_version = 1\n").unwrap();
        assert!(matches!(
            read_active_provider(&config_path),
            ActiveProviderProbe::Unavailable(_)
        ));
    }

    #[test]
    fn active_provider_probe_resolves_deepseek_selection() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(
            &config_path,
            "schema_version = 2\n[provider_activation]\nmode = \"deepseek_responses_text_v1\"\nprofile_id = \"gocode-deepseek-responses-text/1\"\nprofile_digest = \"0112c4b6ce64739810bb79802ebb5ae6fd8ac563d1d1397ac51f07a190538195\"\n",
        )
        .unwrap();
        let probe = read_active_provider(&config_path);
        let ActiveProviderProbe::Live(live) = probe else {
            panic!("expected live probe, got {probe:?}");
        };
        assert_eq!(live.provider, "deepseek");
        assert_eq!(live.model_id, "deepseek-flash");
        assert_eq!(live.profile_id, "gocode-deepseek-responses-text/1");
        std::fs::write(
            &config_path,
            "schema_version = 2\n[provider_activation]\nmode = \"deepseek_responses_text_v1\"\nprofile_id = \"runne-deepseek-responses-text/1\"\nprofile_digest = \"0112c4b6ce64739810bb79802ebb5ae6fd8ac563d1d1397ac51f07a190538195\"\n",
        )
        .unwrap();
        assert!(matches!(
            read_active_provider(&config_path),
            ActiveProviderProbe::Unavailable(_)
        ));
    }

    #[test]
    fn status_lines_never_include_credential_material() {
        let probe = ActiveProviderProbe::Live(ActiveProviderLive {
            mode: "deepseek_responses_text_v1",
            provider: "deepseek",
            profile_id: "gocode-deepseek-responses-text/1".to_owned(),
            model_id: "deepseek-flash".to_owned(),
            model_revision: "2026-09-21".to_owned(),
            config_path: PathBuf::from("unused"),
        });
        let lines = format_status_lines(&probe);
        assert!(lines.contains("provider: deepseek"));
        assert!(lines.contains("model: deepseek-flash"));
        assert!(lines.contains("gocode-deepseek-responses-text/1"));
        assert!(lines.contains("credential: "));
        assert!(!lines.contains("sk-"));
    }
}

/// Formats only the selected provider projection authenticated by the runtime.
fn format_authenticated_provider_statuses(statuses: &[runne_api::ProviderStatusSnapshotV1]) -> Option<String> {
    let status = statuses.iter().find(|status| status.selected())?;
    let readiness = match status.readiness() {
        runne_api::ProviderReadinessStatusV1::Ready => "ready",
        runne_api::ProviderReadinessStatusV1::CredentialMissing => "credential_missing",
        runne_api::ProviderReadinessStatusV1::CredentialAccessDenied => "credential_access_denied",
        runne_api::ProviderReadinessStatusV1::CredentialIdentityMismatch => "credential_identity_mismatch",
        runne_api::ProviderReadinessStatusV1::SecureStoreUnavailable => "secure_store_unavailable",
        runne_api::ProviderReadinessStatusV1::NotSelected => "not_selected",
    };
    Some(format!("provider: {} ({})\nprofile: {}\nreadiness: {} (source: authenticated runtime)", status.provider_id(), status.mode(), status.profile_id(), readiness))
}
