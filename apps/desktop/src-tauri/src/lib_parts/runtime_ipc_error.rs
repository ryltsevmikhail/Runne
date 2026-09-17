// Typed IPC contract for session establishment: the frontend recovers
// automatically only from rejections explicitly marked `transient` (the
// runtime is rotating/reconciling and is expected to become connectable).
// Terminal — and any unknown/malformed availability, including a failed
// availability read — latches the session read-only until manual retry.
#[derive(serde::Serialize, Clone)]
pub struct IpcRuntimeError {
    pub code: &'static str,
    pub disposition: &'static str,
}

pub fn runtime_error_disposition(availability: Option<RuntimeAvailability>) -> &'static str {
    match availability {
        Some(RuntimeAvailability::Reconnecting)
        | Some(RuntimeAvailability::Reconciling) => "transient",
        // Default-deny: terminal, unknown, and availability-read failures.
        _ => "terminal",
    }
}

pub fn commands_admission_error(error: IpcError) -> IpcRuntimeError {
    IpcRuntimeError { code: error.code, disposition: "terminal" }
}

pub fn bootstrap_runtime_error(state: &runne_app_core::AppCore) -> IpcRuntimeError {
    let disposition = runtime_error_disposition(state.runtime_availability().ok());
    IpcRuntimeError { code: "bootstrap_unavailable", disposition }
}

#[cfg(test)]
mod runtime_error_disposition_tests {
    use super::{bootstrap_runtime_error, runtime_error_disposition};
    use runne_app_core::RuntimeAvailability;

    #[test]
    fn explicitly_reconnecting_states_recover_automatically() {
        assert_eq!(runtime_error_disposition(Some(RuntimeAvailability::Reconnecting)), "transient");
        assert_eq!(runtime_error_disposition(Some(RuntimeAvailability::Reconciling)), "transient");
    }

    #[test]
    fn unavailable_reads_are_terminal_not_transient() {
        assert_eq!(runtime_error_disposition(None), "terminal");
        assert_eq!(runtime_error_disposition(Some(RuntimeAvailability::Unconfigured)), "terminal");
        assert_eq!(runtime_error_disposition(Some(RuntimeAvailability::Live)), "terminal");
    }

    #[test]
    fn revoked_incompatible_and_fatal_are_terminal() {
        assert_eq!(runtime_error_disposition(Some(RuntimeAvailability::Incompatible)), "terminal");
        assert_eq!(runtime_error_disposition(Some(RuntimeAvailability::Revoked)), "terminal");
        assert_eq!(runtime_error_disposition(Some(RuntimeAvailability::Fatal)), "terminal");
    }

    #[test]
    fn bootstrap_command_error_default_denies_a_real_core() {
        use runne_app_core::{AppCore, RuntimeMode};
        let temporary = tempfile::tempdir().expect("temporary profile");
        let core = AppCore::open_with_runtime_mode(
            &temporary.path().join("profile.sqlite3"),
            RuntimeMode::Bundled,
        )
        .expect("open bundled core");
        // The get_bootstrap error constructor against a real configured core:
        // a state that is not provably reconnecting must deny auto-recovery.
        let error = bootstrap_runtime_error(&core);
        assert_eq!(error.code, "bootstrap_unavailable");
        assert_eq!(error.disposition, "terminal");
    }
}
