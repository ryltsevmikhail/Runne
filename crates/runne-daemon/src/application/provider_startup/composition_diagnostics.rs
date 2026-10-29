use crate::error::DaemonError;

#[path = "composition_status.rs"]
mod status;
pub(super) fn pending(db_path: &str, protected: bool) {
    if protected {
        status::publish(db_path, "provider_compose_pending");
    }
}
pub(super) fn record_result(
    db_path: &str,
    protected: bool,
    has_service: bool,
    error: Option<&DaemonError>,
) {
    let (stage, succeeded) = match (has_service, error) {
        (true, None) => ("provider_compose_ready", true),
        (false, None) => ("provider_compose_none", true),
        (_, Some(error)) => (failure_stage(error), false),
    };
    crate::protected_activation::linux_pair_diagnostics::record(stage, succeeded);
    if protected {
        status::publish(db_path, stage);
    }
    if !succeeded {
        // Closed vocabulary only: never print the underlying error or its data.
        eprintln!("runne-provider-startup: {stage}");
    }
}

fn failure_stage(error: &DaemonError) -> &'static str {
    let DaemonError::Bootstrap(message) = error else {
        return match error {
            DaemonError::StoreOpenRejection(_) => "provider_compose_store_open",
            DaemonError::Config(_) => "provider_compose_config",
            DaemonError::Io(_) => "provider_compose_io",
            DaemonError::Schema(_) => "provider_compose_schema",
            DaemonError::Lock(_) => "provider_compose_lock",
            DaemonError::Bootstrap(_) => unreachable!(),
        };
    };
    if let Some(code) = CLOSED_GATE_CODES.iter().find(|code| **code == message) {
        return code;
    }
    match message.as_str() {
        "provider dependencies unavailable" => "provider_compose_dependencies",
        "provider selection unavailable" => "provider_compose_selection",
        "provider runne-secure-store backend unsupported" => "provider_compose_secure_backend",
        "provider profile binding mismatch" => "provider_compose_profile_binding",
        "provider dispatch store unavailable"
        | "provider execution store unavailable"
        | "provider scanner recovery unavailable" => "provider_compose_provider_stores",
        "provider authority unavailable" => "provider_compose_authority",
        "adopted credential database unavailable"
        | "adopted credential database does not match protected owner"
        | "adopted credential source does not match"
        | "adoption requires the existing standalone DeepSeek text installation"
        | "adoption runtime root is not owner-private"
        | "adoption authority unavailable"
        | "adoption anchor conflicts"
        | "running host image differs from installed image"
        | "credential host image changed"
        | "credential host configuration changed" => "provider_compose_adopted_source",
        "tool provider unavailable" => "provider_compose_tool_transport",
        "D2 tool grant unavailable" => "provider_compose_tool_grant",
        "provider credential lifecycle unavailable"
        | "provider credential unavailable"
        | "provider credential reader unavailable"
        | "provider credential identity unavailable"
        | "credential reader probe unavailable" => "provider_compose_credential_reader",
        "provider credential control unavailable"
        | "credential enrollment recovery unavailable" => "provider_compose_credential_recovery",
        "provider journal key unavailable" => "provider_compose_journal_key",
        "provider online effect proof unavailable" => "provider_compose_effect_proof",
        "provider recovery unavailable" => "provider_compose_recovery",
        _ => "provider_compose_other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_codes_are_exact_bounded_and_do_not_echo_unknown_details() {
        for code in CLOSED_GATE_CODES {
            assert!(code.len() <= 64);
            assert_eq!(
                failure_stage(&DaemonError::Bootstrap((*code).into())),
                *code
            );
        }
        assert_eq!(
            failure_stage(&DaemonError::Bootstrap(
                "provider_compose_adopted_target arbitrary detail".into()
            )),
            "provider_compose_other"
        );
    }
    #[test]
    fn composition_failure_classification_is_closed() {
        assert_eq!(
            failure_stage(&DaemonError::Bootstrap(
                "adopted credential source does not match".to_owned()
            )),
            "provider_compose_adopted_source"
        );
        assert_eq!(
            failure_stage(&DaemonError::Bootstrap(
                "provider journal key unavailable".to_owned()
            )),
            "provider_compose_journal_key"
        );
        assert_eq!(
            failure_stage(&DaemonError::Bootstrap(
                "secret-bearing or dynamic details".to_owned()
            )),
            "provider_compose_other"
        );
        assert_eq!(
            failure_stage(&DaemonError::Config(
                "arbitrary configuration detail".to_owned()
            )),
            "provider_compose_config"
        );
    }
}

const CLOSED_GATE_CODES: &[&str] = &[
    "provider_compose_access_policy",
    "provider_compose_native_reader",
    "provider_compose_primary_adapter",
    "provider_compose_adopted_database",
    "provider_compose_adopted_binding",
    "provider_compose_adopted_owner",
    "provider_compose_adopted_witness",
    "provider_compose_adopted_access",
    "provider_compose_adopted_config",
    "provider_compose_adopted_config_policy",
    "provider_compose_adopted_layout",
    "provider_compose_adopted_image_open",
    "provider_compose_adopted_image_alias",
    "provider_compose_adopted_image_owner",
    "provider_compose_adopted_image_pins",
    "provider_compose_adopted_running_image",
    "provider_compose_adopted_config_changed",
    "provider_compose_adopted_image_changed",
    "provider_compose_adopted_target",
];
