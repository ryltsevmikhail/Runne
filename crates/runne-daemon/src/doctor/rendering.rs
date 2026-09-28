//! Text and JSON renderings of the doctor report: one shared check list
//! feeds both formats (D1.5 format parity), plus the readiness projection.

use crate::provider_activation::ProviderActivation;

use super::{CredentialDisposition, DoctorReport, credential_source, readiness};

/// One doctor check with a stable id and closed outcome, shared by the text
/// and JSON renderings (D1.5 format parity, 2026-09-28).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorCheck {
    /// Stable bracketed id, identical in both renderings.
    pub id: &'static str,
    /// Closed outcome: `pass`, `warn`, or `fail`.
    pub status: &'static str,
}

/// The full check list of the report; the text rendering carries the same
/// ids as bracketed line suffixes.
#[must_use]
pub fn doctor_checks(report: &DoctorReport) -> Vec<DoctorCheck> {
    let mut checks = vec![DoctorCheck {
        id: if report.config_present {
            "config.present"
        } else {
            "config.absent"
        },
        status: "pass",
    }];
    if let Some(problem) = &report.config_problem {
        checks.push(DoctorCheck {
            id: problem.id,
            status: "fail",
        });
    }
    checks.push(DoctorCheck {
        id: "provider.active",
        status: if report.active_provider.is_some() {
            "pass"
        } else {
            "warn"
        },
    });
    for (id, disposition) in [
        ("credential.openai", &report.openai_credential),
        ("credential.deepseek", &report.deepseek_credential),
    ] {
        let status = match disposition {
            CredentialDisposition::Configured => "pass",
            CredentialDisposition::Missing => "warn",
            _ => "fail",
        };
        checks.push(DoctorCheck { id, status });
    }
    checks.push(DoctorCheck {
        id: "execution.ready",
        status: if report.execution_ready() {
            "pass"
        } else {
            "fail"
        },
    });
    checks.extend(readiness::collect());
    checks
}

/// Formats the report as one redacted JSON object with the same check ids as
/// the text rendering.
#[must_use]
pub fn format_report_json(report: &DoctorReport) -> String {
    let checks: Vec<serde_json::Value> = doctor_checks(report)
        .into_iter()
        .map(|check| serde_json::json!({ "id": check.id, "status": check.status }))
        .collect();
    let document = serde_json::json!({
        "schemaVersion": 1,
        "executionReady": report.execution_ready(),
        "checks": checks,
    });
    format!("{document}")
}

/// Formats the report as stable text without secret material.
#[must_use]
pub fn format_report(report: &DoctorReport) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    let _ = writeln!(
        output,
        "config: user-local external configuration ({}) [config.{}]",
        if report.config_present {
            "present"
        } else {
            "missing"
        },
        if report.config_present {
            "present"
        } else {
            "absent"
        }
    );
    match &report.active_provider {
        None => {
            let _ = writeln!(
                output,
                "active provider: none (deterministic_v1) [provider.active]"
            );
        }
        Some(info) => {
            let _ = writeln!(
                output,
                "active provider: {} ({} [provider.active])",
                info.activation.binding().mode().as_str(),
                match &info.activation {
                    ProviderActivation::Deterministic(_) => "deterministic",
                    ProviderActivation::OpenAiResponsesText(_) => "openai",
                    ProviderActivation::DeepSeekResponsesText(_) => "deepseek",
                    ProviderActivation::ZaiCodingChatCompletionsText(_) => "zai",
                    ProviderActivation::QwenCloudTokenChatCompletionsText(_) =>
                        "qwen-token-plan-individual",
                    ProviderActivation::GenericChatCompletionsText(binding) => binding
                        .profile_id()
                        .strip_prefix("gocode-chat-completions/")
                        .unwrap_or("generic"),
                    ProviderActivation::LocalEngineText(_) => "local-engine",
                    ProviderActivation::NativeText(..) => "native",
                    ProviderActivation::RadiusText(..) => "radius",
                    ProviderActivation::ResponsesText(binding, _) => binding
                        .profile_id()
                        .strip_prefix("gocode-responses/")
                        .and_then(|value| value.split('/').next())
                        .unwrap_or("responses"),
                    ProviderActivation::CloudText(binding, _) => binding
                        .profile_id()
                        .strip_prefix("gocode-cloud/")
                        .and_then(|value| value.split('/').next())
                        .unwrap_or("cloud"),
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
        "credential openai: {} (source: {}) [credential.openai]",
        report.openai_credential.as_str(),
        credential_source()
    );
    let _ = writeln!(
        output,
        "credential deepseek: {} (source: {}) [credential.deepseek]",
        report.deepseek_credential.as_str(),
        credential_source()
    );
    if let Some(problem) = &report.config_problem {
        // Closed classification only: no path, no config content, no raw
        // error text; the stable id stays at the end of the line.
        let _ = writeln!(output, "{}", problem.render());
    }
    let _ = writeln!(
        output,
        "execution ready: {} [execution.ready]",
        if report.execution_ready() {
            "yes"
        } else {
            "no"
        }
    );
    for check in readiness::collect() {
        let _ = writeln!(
            output,
            "readiness: {} {} [{}]",
            detail_of(&check),
            check.status,
            check.id
        );
    }
    output
}

/// Closed single-word fact for a readiness check line.
fn detail_of(check: &DoctorCheck) -> &'static str {
    match check.id {
        "readiness.db_integrity" => "database",
        "readiness.terminal_outbox" => "terminal outbox",
        "readiness.uncertain_attempts" => "uncertain attempts",
        "readiness.text_only_path" => "text-only path",
        "readiness.tools_disabled" => "tools disabled",
        _ => "check",
    }
}
