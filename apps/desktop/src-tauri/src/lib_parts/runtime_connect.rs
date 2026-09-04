#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn connect_runtime(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    updates: State<'_, crate::UpdateStatusStore>,
) -> Result<RuntimeAvailability, IpcError> {
    require_runtime_admission(&lifecycle)?;
    let availability = lifecycle.connect_runtime(&state).await
        .map_err(|_| IpcError { code: "runtime_connection_unavailable" })?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if availability == RuntimeAvailability::Live {
        crate::provider_credential_enrollment::reconcile_startup(&lifecycle, &updates).await
            .map_err(|()| IpcError { code: "runtime_credential_cleanup_incomplete" })?;
    }
    let terminal = matches!(availability, RuntimeAvailability::Incompatible | RuntimeAvailability::Revoked | RuntimeAvailability::Fatal);
    if availability == RuntimeAvailability::Live || terminal {
        let _ = updates.complete_health_if_pending(availability == RuntimeAvailability::Live);
    }
    Ok(availability)
}
