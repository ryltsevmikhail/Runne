#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn connect_runtime(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    updates: State<'_, crate::UpdateStatusStore>,
) -> Result<RuntimeAvailability, IpcRuntimeError> {
    require_runtime_admission(&lifecycle)
        .map_err(commands_admission_error)?;
    let availability = lifecycle.connect_runtime(&state).await
        .map_err(|_| {
            // A shutdown race must stay terminal even when the AppCore state
            // still looks transient.
            if lifecycle.is_shutting_down() {
                return IpcRuntimeError {
                    code: "runtime_shutdown_in_progress",
                    disposition: "terminal",
                };
            }
            IpcRuntimeError {
                code: "runtime_connection_unavailable",
                disposition: runtime_error_disposition(state.runtime_availability().ok()),
            }
        })?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if availability == RuntimeAvailability::Live {
        crate::provider_credential_enrollment::reconcile_startup(&lifecycle, &updates).await
            .map_err(|_| IpcRuntimeError { code: "runtime_credential_cleanup_incomplete", disposition: "terminal" })?;
    }
    // An explicit quit during the await must stay terminal even if the
    // handshake itself succeeded.
    if lifecycle.is_shutting_down() {
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
