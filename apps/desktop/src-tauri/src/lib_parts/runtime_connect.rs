#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn connect_runtime(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    updates: State<'_, crate::UpdateStatusStore>,
) -> Result<RuntimeAvailability, IpcRuntimeError> {
    if let Err(error) = require_runtime_admission(&lifecycle) {
        crate::runtime_status_qualification::record(
            crate::runtime_status_qualification::Operation::Connect,
            crate::runtime_status_qualification::Outcome::Rejected,
            crate::runtime_status_qualification::Disposition::Terminal,
            None,
        );
        return Err(commands_admission_error(&error));
    }
    let Ok(availability) = lifecycle.connect_runtime(&state).await else {
        // A shutdown race must stay terminal even when the AppCore state
        // still looks transient.
        if lifecycle.is_shutting_down() {
            crate::runtime_status_qualification::record(
                crate::runtime_status_qualification::Operation::Connect,
                crate::runtime_status_qualification::Outcome::Rejected,
                crate::runtime_status_qualification::Disposition::Terminal,
                None,
            );
            return Err(IpcRuntimeError {
                code: "runtime_shutdown_in_progress",
                disposition: "terminal",
            });
        }
        let runtime = state.runtime_availability().ok();
        let disposition = runtime_error_disposition(runtime);
        crate::runtime_status_qualification::record(
            crate::runtime_status_qualification::Operation::Connect,
            crate::runtime_status_qualification::Outcome::Rejected,
            crate::runtime_status_qualification::disposition_from_ipc(disposition),
            runtime,
        );
        return Err(IpcRuntimeError {
            code: "runtime_connection_unavailable",
            disposition,
        });
    };
    crate::runtime_status_qualification::record(
        crate::runtime_status_qualification::Operation::Connect,
        crate::runtime_status_qualification::Outcome::State,
        crate::runtime_status_qualification::disposition_for(Some(availability)),
        Some(availability),
    );
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if availability == RuntimeAvailability::Live {
        crate::provider_credential_enrollment::reconcile_startup(&lifecycle, &updates).await
            .map_err(|()| IpcRuntimeError { code: "runtime_credential_cleanup_incomplete", disposition: "terminal" })?;
    }
    // An explicit quit during the await must stay terminal even if the
    // handshake itself succeeded.
    if lifecycle.is_shutting_down() {
        crate::runtime_status_qualification::record(
            crate::runtime_status_qualification::Operation::Connect,
            crate::runtime_status_qualification::Outcome::Rejected,
            crate::runtime_status_qualification::Disposition::Terminal,
            Some(availability),
        );
        return Err(IpcRuntimeError {
            code: "runtime_shutdown_in_progress",
            disposition: "terminal",
        });
    }
    let terminal = matches!(availability, RuntimeAvailability::Incompatible | RuntimeAvailability::Revoked | RuntimeAvailability::Fatal);
    if availability == RuntimeAvailability::Live || terminal {
        let _ = updates.complete_health_if_pending(availability == RuntimeAvailability::Live);
    }
    Ok(availability)
}
