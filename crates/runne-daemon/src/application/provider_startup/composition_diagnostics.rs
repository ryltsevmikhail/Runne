use crate::error::DaemonError;

pub(super) fn record_result(has_service: bool, error: Option<&DaemonError>) {
    let (stage, succeeded) = match (has_service, error) {
        (true, None) => ("provider_compose_ready", true),
        (false, None) => ("provider_compose_none", true),
        (_, Some(error)) => (failure_stage(error), false),
    };
    crate::protected_activation::linux_pair_diagnostics::record(stage, succeeded);
}

fn failure_stage(error: &DaemonError) -> &'static str {
    let DaemonError::Bootstrap(message) = error else {
        return "provider_compose_other";
    };
    match message.as_str() {
        "provider profile binding mismatch" => "provider_compose_profile_binding",
        "provider dispatch store unavailable"
        | "provider execution store unavailable"
        | "provider scanner recovery unavailable" => "provider_compose_provider_stores",
        "provider authority unavailable" => "provider_compose_authority",
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
    fn composition_failure_classification_is_closed() {
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
            "provider_compose_other"
        );
    }
}
