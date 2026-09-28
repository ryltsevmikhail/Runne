//! Metadata-only provider readiness diagnostics for `runned doctor`.
//!
//! Runs before bootstrap and before the protected-activation channel: reads
//! only the non-secret external configuration. Authoritative credential state
//! remains daemon-owned and is reported as missing until runtime status is open.

use runne_secure_store::ProviderCredentialId;

use crate::config::{external_config_path, load_external_config};
use crate::provider_activation::ProviderActivation;
mod active_provider;
mod config_problem;
mod provider_credentials;
mod readiness;
mod rendering;
use active_provider::active_provider_info;
use config_problem::{ConfigProblem, classify_config_error};
use provider_credentials::credential_disposition;
pub use provider_credentials::{CredentialDisposition, credential_source};
pub use rendering::{DoctorCheck, doctor_checks, format_report, format_report_json};

/// Non-secret description of the exact active provider selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProviderInfo {
    /// Exact activation retained for readiness classification.
    pub activation: ProviderActivation,
    pub profile_id: String,
    pub model_id: String,
    pub model_revision: String,
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
    /// True when the external config file exists on disk. The location itself
    /// is never retained: the report carries no path by construction.
    pub config_present: bool,
    /// `None` means the deterministic default (no live provider selected).
    pub active_provider: Option<ActiveProviderInfo>,
    pub openai_credential: CredentialDisposition,
    pub deepseek_credential: CredentialDisposition,
    /// Closed classification of a config load problem; the rest of the report
    /// stays complete. `None` means the config loaded (or is absent by
    /// deterministic default).
    pub config_problem: Option<ConfigProblem>,
}

impl DoctorReport {
    /// True when provider execution could start: deterministic mode, or the
    /// exact active provider credential is configured and config loaded.
    #[must_use]
    pub fn execution_ready(&self) -> bool {
        if self.config_problem.is_some() {
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
                ProviderActivation::ZaiCodingChatCompletionsText(_)
                | ProviderActivation::QwenCloudTokenChatCompletionsText(_)
                | ProviderActivation::GenericChatCompletionsText(_)
                | ProviderActivation::NativeText(..)
                | ProviderActivation::RadiusText(..)
                | ProviderActivation::ResponsesText(..)
                | ProviderActivation::CloudText(..) => self
                    .active_credential(info)
                    .is_some_and(CredentialDisposition::is_configured),
                ProviderActivation::LocalEngineText(_) => true,
            },
        }
    }

    fn active_credential(&self, info: &ActiveProviderInfo) -> Option<CredentialDisposition> {
        let account = match &info.activation {
            ProviderActivation::ZaiCodingChatCompletionsText(_) => "zai",
            ProviderActivation::QwenCloudTokenChatCompletionsText(_) => {
                "qwen-token-plan-individual"
            }
            ProviderActivation::GenericChatCompletionsText(binding)
            | ProviderActivation::NativeText(binding, _)
            | ProviderActivation::RadiusText(binding, _)
            | ProviderActivation::ResponsesText(binding, _)
            | ProviderActivation::CloudText(binding, _) => binding
                .profile_id()
                .split('/')
                .find(|part| ProviderCredentialId::from_account(part).is_some())?,
            _ => return None,
        };
        ProviderCredentialId::from_account(account).map(credential_disposition)
    }
}

/// Runs every metadata-only probe without bootstrapping the daemon.
#[must_use]
pub fn run_doctor() -> DoctorReport {
    // The resolved location is used only for the presence probe and is never
    // stored in the report: redaction by construction, not by formatting.
    let config_path = external_config_path();
    let config_present = std::fs::symlink_metadata(&config_path).is_ok();
    let (activation, config_problem) = match load_external_config() {
        Ok(snapshot) => (snapshot.provider_activation, None),
        Err(error) => (
            ProviderActivation::deterministic_v1(),
            Some(classify_config_error(&error)),
        ),
    };
    let active_provider = active_provider_info(&activation);
    DoctorReport {
        config_present,
        active_provider,
        openai_credential: credential_disposition(ProviderCredentialId::OpenAi),
        deepseek_credential: credential_disposition(ProviderCredentialId::DeepSeek),
        config_problem,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DaemonError;
    use runne_provider_deepseek::{DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION};

    #[test]
    fn deterministic_default_is_execution_ready_without_credential() {
        let report = DoctorReport {
            config_present: false,
            active_provider: None,
            openai_credential: CredentialDisposition::Missing,
            deepseek_credential: CredentialDisposition::Missing,
            config_problem: None,
        };
        assert!(report.execution_ready());
        let formatted = format_report(&report);
        assert!(formatted.contains("active provider: none"));
        assert!(formatted.contains("execution ready: yes"));
        assert!(formatted.contains("[config.absent]"));
        assert!(!formatted.contains("configured"));
    }

    #[test]
    fn deepseek_execution_requires_the_deepseek_credential() {
        let report = DoctorReport {
            config_present: true,
            active_provider: Some(ActiveProviderInfo {
                activation: ProviderActivation::DeepSeekResponsesText(
                    runne_api::ProviderActivationBindingV1::deepseek_responses_text_v1(),
                ),
                profile_id: "gocode-deepseek-responses-text/1".to_owned(),
                model_id: DEEPSEEK_MODEL_ID.to_owned(),
                model_revision: DEEPSEEK_MODEL_REVISION.to_owned(),
            }),
            openai_credential: CredentialDisposition::Configured,
            deepseek_credential: CredentialDisposition::Missing,
            config_problem: None,
        };
        assert!(!report.execution_ready());
        let formatted = format_report(&report);
        assert!(formatted.contains("credential deepseek: missing"));
        assert!(formatted.contains("model: deepseek-flash"));
        assert!(formatted.contains("[config.present]"));
    }

    #[test]
    fn config_problem_blocks_execution_readiness_without_the_raw_error() {
        let report = DoctorReport {
            config_present: true,
            active_provider: None,
            openai_credential: CredentialDisposition::Unavailable,
            deepseek_credential: CredentialDisposition::Unavailable,
            config_problem: Some(classify_config_error(&DaemonError::Config(
                "external config is not owner-private".to_owned(),
            ))),
        };
        assert!(!report.execution_ready());
        let formatted = format_report(&report);
        let line = formatted
            .lines()
            .find(|line| line.contains("[config.not_owner_private]"))
            .expect("classified config line present");
        assert!(line.starts_with("config problem: "));
        assert!(line.ends_with("[config.not_owner_private]"));
        assert!(!formatted.contains("config error:"));
    }
}

#[cfg(test)]
mod config_problem_tests;
