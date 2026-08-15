use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_app_core::{AppCore, OperationalTelemetrySnapshotV1};
use tauri::State;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::IpcError;

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
#[cfg_attr(test, allow(dead_code))]
pub async fn get_operational_telemetry(
    state: State<'_, Arc<AppCore>>,
) -> Result<OperationalTelemetrySnapshotV1, IpcError> {
    operational_telemetry_from_core(Arc::clone(state.inner())).await
}

pub async fn operational_telemetry_from_core(
    core: Arc<AppCore>,
) -> Result<OperationalTelemetrySnapshotV1, IpcError> {
    operational_telemetry_from_core_with_gate(core, Arc::clone(telemetry_gate())).await
}

pub async fn operational_telemetry_from_core_with_gate(
    core: Arc<AppCore>,
    gate: Arc<Semaphore>,
) -> Result<OperationalTelemetrySnapshotV1, IpcError> {
    let permit = gate.try_acquire_owned().map_err(|_| unavailable())?;
    run_telemetry_blocking(permit, move || {
        let observed_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unavailable())?
            .as_secs();
        operational_telemetry_at(&core, observed_at_unix_seconds)
    })
    .await
}

pub async fn run_telemetry_blocking<T, F>(
    permit: OwnedSemaphorePermit,
    projection: F,
) -> Result<T, IpcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, IpcError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        projection()
    })
    .await
    .map_err(|_| unavailable())?
}

fn telemetry_gate() -> &'static Arc<Semaphore> {
    static GATE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    GATE.get_or_init(|| Arc::new(Semaphore::new(1)))
}

pub fn operational_telemetry_at(
    core: &AppCore,
    observed_at_unix_seconds: u64,
) -> Result<OperationalTelemetrySnapshotV1, IpcError> {
    core.operational_telemetry_snapshot(observed_at_unix_seconds)
        .map_err(|_| unavailable())
}

const fn unavailable() -> IpcError {
    IpcError {
        code: "operational_telemetry_unavailable",
    }
}
