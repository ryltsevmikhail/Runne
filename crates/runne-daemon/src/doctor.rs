//! Metadata-only provider readiness diagnostics for `runned doctor`.
//!
//! Runs before bootstrap and before the protected-activation channel: reads
//! only the non-secret external configuration. Authoritative credential state
//! remains daemon-owned and is reported as missing until runtime status is open.

use std::path::PathBuf;

use runne_provider_deepseek::{DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION};
use runne_provider_openai::{OPENAI_MODEL_ID, OPENAI_MODEL_REVISION};
use runne_secure_store::ProviderCredentialId;

use crate::config::{external_config_path, load_external_config};
use crate::provider_activation::ProviderActivation;
mod provider_credentials;
use provider_credentials::credential_disposition;
pub use provider_credentials::{CredentialDisposition, credential_source};

/// Non-secret description of the exact active provider selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProviderInfo {
    /// Exact activation retained for readiness classification.
    pub activation: ProviderActivation,
    pub profile_id: String,
    pub model_id: &'static str,
    pub model_revision: &'static str,
}

impl ActiveProviderInfo {
    /// Exact non-secret activation mode string.
    #[must_use]
    pub fn mode(&self) -> &'static str {
        self.activation.binding().mode().as_str()
    }
}

/// Complete metadata-only diagnostic report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorReport {
    pub config_path: PathBuf,
    /// True when the external config file exists on disk.
    pub config_present: bool,
    /// `None` means the deterministic default (no live provider selected).
    pub active_provider: Option<ActiveProviderInfo>,
    pub openai_credential: CredentialDisposition,
    pub deepseek_credential: CredentialDisposition,
    /// Non-secret config load problem; the rest of the report stays complete.
    pub config_error: Option<String>,
}

impl DoctorReport {
    /// True when provider execution could start: deterministic mode, or the
    /// exact active provider credential is configured and config loaded.
    #[must_use]
    pub fn execution_ready(&self) -> bool {
        if self.config_error.is_some() {
            return false;
        }
        match &self.active_provider {
            None => true,
            Some(info) => match info.activation {
                ProviderActivation::Deterministic(_) => true,
                ProviderActivation::OpenAiResponsesText(_) => {
                    self.openai_credential.is_configured()
                }
                ProviderActivation::DeepSeekResponsesText(_) => {
                    self.deepseek_credential.is_configured()
                }
            },
        }
    }
}

fn active_provider_info(activation: &ProviderActivation) -> Option<ActiveProviderInfo> {
    match activation {
        ProviderActivation::Deterministic(_) => None,
        ProviderActivation::OpenAiResponsesText(binding) => Some(ActiveProviderInfo {
            activation: activation.clone(),
            profile_id: binding.profile_id().to_owned(),
            model_id: OPENAI_MODEL_ID,
            model_revision: OPENAI_MODEL_REVISION,
        }),
        ProviderActivation::DeepSeekResponsesText(binding) => Some(ActiveProviderInfo {
            activation: activation.clone(),
            profile_id: binding.profile_id().to_owned(),
            model_id: DEEPSEEK_MODEL_ID,
            model_revision: DEEPSEEK_MODEL_REVISION,
        }),
    }
}

/// Runs every metadata-only probe without bootstrapping the daemon.
#[must_use]
pub fn run_doctor() -> DoctorReport {
    let config_path = external_config_path();
    let config_present = std::fs::symlink_metadata(&config_path).is_ok();
    let (activation, config_error) = match load_external_config() {
        Ok(snapshot) => (snapshot.provider_activation, None),
        Err(error) => (
            ProviderActivation::deterministic_v1(),
            Some(error.to_string()),
        ),
    };
    let active_provider = active_provider_info(&activation);
    DoctorReport {
        config_path,
        config_present,
        active_provider,
        openai_credential: credential_disposition(ProviderCredentialId::OpenAi),
        deepseek_credential: credential_disposition(ProviderCredentialId::DeepSeek),
        config_error,
    }
}

/// Formats the report as stable text without secret material.
#[must_use]
pub fn format_report(report: &DoctorReport) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    let _ = writeln!(
        output,
        "config: {} ({})",
        report.config_path.display(),
        if report.config_present {
            "present"
        } else {
            "missing"
        }
    );
    match &report.active_provider {
        None => {
            let _ = writeln!(output, "active provider: none (deterministic_v1)");
        }
        Some(info) => {
            let _ = writeln!(
                output,
                "active provider: {} ({})",
                info.activation.binding().mode().as_str(),
                match info.activation {
                    ProviderActivation::Deterministic(_) => "deterministic",
                    ProviderActivation::OpenAiResponsesText(_) => "openai",
                    ProviderActivation::DeepSeekResponsesText(_) => "deepseek",
                }
            );
            let _ = writeln!(output, "profile: {}", info.profile_id);
            let _ = writeln!(
                output,
                "model: {} (revision {})",
                info.model_id, info.model_revision
            );
        }
    }
    let _ = writeln!(
        output,
        "credential openai: {} (source: {})",
        report.openai_credential.as_str(),
        credential_source()
    );
    let _ = writeln!(
        output,
        "credential deepseek: {} (source: {})",
        report.deepseek_credential.as_str(),
        credential_source()
    );
    if let Some(error) = &report.config_error {
        let _ = writeln!(output, "config error: {error}");
    }
    let _ = writeln!(
        output,
        "execution ready: {}",
        if report.execution_ready() {
            "yes"
        } else {
            "no"
        }
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_default_is_execution_ready_without_credential() {
        let report = DoctorReport {
            config_path: PathBuf::from("unused"),
            config_present: false,
            active_provider: None,
            openai_credential: CredentialDisposition::Missing,
            deepseek_credential: CredentialDisposition::Missing,
            config_error: None,
        };
        assert!(report.execution_ready());
        let formatted = format_report(&report);
        assert!(formatted.contains("active provider: none"));
        assert!(formatted.contains("execution ready: yes"));
        assert!(!formatted.contains("configured"));
    }

    #[test]
    fn deepseek_execution_requires_the_deepseek_credential() {
        let report = DoctorReport {
            config_path: PathBuf::from("unused"),
            config_present: true,
            active_provider: Some(ActiveProviderInfo {
                activation: ProviderActivation::DeepSeekResponsesText(
                    runne_api::ProviderActivationBindingV1::deepseek_responses_text_v1(),
                ),
                profile_id: "gocode-deepseek-responses-text/1".to_owned(),
                model_id: DEEPSEEK_MODEL_ID,
                model_revision: DEEPSEEK_MODEL_REVISION,
            }),
            openai_credential: CredentialDisposition::Configured,
            deepseek_credential: CredentialDisposition::Missing,
            config_error: None,
        };
        assert!(!report.execution_ready());
        let formatted = format_report(&report);
        assert!(formatted.contains("credential deepseek: missing"));
        assert!(formatted.contains("model: deepseek-chat"));
    }

    #[test]
    fn config_error_blocks_execution_readiness() {
        let report = DoctorReport {
            config_path: PathBuf::from("unused"),
            config_present: true,
            active_provider: None,
            openai_credential: CredentialDisposition::Unavailable,
            deepseek_credential: CredentialDisposition::Unavailable,
            config_error: Some("external config is not owner-private".to_owned()),
        };
        assert!(!report.execution_ready());
        let formatted = format_report(&report);
        assert!(formatted.contains("config error:"));
    }
}
