use super::{ActiveSignedLinuxV3Marker, BundledRuntimeController};
use crate::{AppCoreError, bundled_runtime::linux_v3_latch};
use runne_app_core::RuntimeAvailability;
use runne_platform_desktop::ProtectedBundledRuntimeError;
use tauri::Manager as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Route {
    Baseline,
    Transition,
    VerifyV3,
    RejectDowngrade,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Evidence {
    Present,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PendingProfile {
    V2,
    V3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RouteState {
    pub(super) installed_tuple: Evidence,
    pub(super) signed_v3_latch: Evidence,
    pub(super) pending_profile: PendingProfile,
    pub(super) active_v3_marker: Evidence,
}

impl From<(bool, bool, bool, bool)> for RouteState {
    fn from((installed, latched, profile_v3, marker): (bool, bool, bool, bool)) -> Self {
        Self {
            installed_tuple: evidence(installed),
            signed_v3_latch: evidence(latched),
            pending_profile: if profile_v3 {
                PendingProfile::V3
            } else {
                PendingProfile::V2
            },
            active_v3_marker: evidence(marker),
        }
    }
}

const fn evidence(present: bool) -> Evidence {
    if present {
        Evidence::Present
    } else {
        Evidence::Absent
    }
}

pub(super) fn route(state: RouteState) -> Route {
    if state.installed_tuple == Evidence::Absent {
        return if state.signed_v3_latch == Evidence::Present
            || state.pending_profile == PendingProfile::V3
            || state.active_v3_marker == Evidence::Present
        {
            Route::RejectDowngrade
        } else {
            Route::Baseline
        };
    }
    if state.pending_profile == PendingProfile::V3 {
        return if state.active_v3_marker == Evidence::Present {
            Route::VerifyV3
        } else {
            Route::RejectDowngrade
        };
    }
    Route::Transition
}

pub(super) async fn transition_and_install(
    controller: &BundledRuntimeController,
    lease: runne_app_core::BundledRuntimeActivationLease,
    mut installed: crate::updater_status::enrollment::NativeInstalledEnrollmentLease,
) -> Result<RuntimeAvailability, AppCoreError> {
    // Authenticate V2 so the supervisor can confirm the signed tuple. This
    // client stays host-local and is never installed into AppCore.
    connect_and_record_ready(controller).await?;
    ensure_not_stopping(controller)?;
    installed
        .refresh_linux()
        .map_err(|()| AppCoreError::RuntimeUnavailable)?;
    let prepared = installed
        .take_prepared()
        .map_err(|()| AppCoreError::RuntimeUnavailable)?;
    let confirmed = controller
        .run_supervisor(move |supervisor| supervisor.confirm_installed_native_enrollment(prepared))
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    installed
        .revalidate_confirmed(&confirmed)
        .map_err(|()| AppCoreError::RuntimeUnavailable)?;

    let latch_path = controller.signed_linux_v3_latch_path.clone();
    let app = controller
        .startup_app
        .lock()
        .map_err(|_| AppCoreError::RuntimeUnavailable)?
        .clone()
        .ok_or(AppCoreError::RuntimeUnavailable)?;
    let hint = app
        .path()
        .resource_dir()
        .map_err(|_| AppCoreError::RuntimeUnavailable)?
        .to_str()
        .ok_or(AppCoreError::RuntimeUnavailable)?
        .to_owned();
    let confirmed = controller
        .run_supervisor(move |supervisor| {
            linux_v3_latch::persist_before_transition(
                &latch_path,
                || {
                    supervisor
                        .begin_confirmed_linux_credential_enrollment_transition(&confirmed, &hint)
                },
                |_| ProtectedBundledRuntimeError::InvalidState,
            )?;
            Ok(confirmed)
        })
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;

    let profile = controller
        .supervisor
        .lock()
        .map_err(|_| AppCoreError::RuntimeUnavailable)?
        .take_runtime_profile()
        .ok_or(AppCoreError::RuntimeUnavailable)?;
    let v3 = profile
        .connect(super::BUNDLED_CLIENT_CONNECT_TIMEOUT)
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    let readiness = v3.clone();
    controller
        .run_supervisor(move |supervisor| supervisor.record_client_ready(&readiness))
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    ensure_not_stopping(controller)?;
    installed
        .revalidate_confirmed(&confirmed)
        .map_err(|()| AppCoreError::RuntimeUnavailable)?;
    let marker = ActiveSignedLinuxV3Marker::from_confirmed(&confirmed)
        .ok_or(AppCoreError::RuntimeUnavailable)?;
    *controller
        .active_signed_linux_v3
        .lock()
        .map_err(|_| AppCoreError::RuntimeUnavailable)? = Some(marker);
    controller.arm_renewal_schedule()?;
    controller
        .core
        .install_bundled_runtime_client(lease, v3)
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    Ok(RuntimeAvailability::Live)
}

async fn connect_and_record_ready(
    controller: &BundledRuntimeController,
) -> Result<(), AppCoreError> {
    let profile = controller
        .supervisor
        .lock()
        .map_err(|_| AppCoreError::RuntimeUnavailable)?
        .take_runtime_profile()
        .ok_or(AppCoreError::RuntimeUnavailable)?;
    let client = profile
        .connect(super::BUNDLED_CLIENT_CONNECT_TIMEOUT)
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    let readiness = client.clone();
    controller
        .run_supervisor(move |supervisor| supervisor.record_client_ready(&readiness))
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    Ok(())
}

pub(super) async fn confirm_current_marker(
    controller: &BundledRuntimeController,
    installed: &mut crate::updater_status::enrollment::NativeInstalledEnrollmentLease,
    previous: Option<ActiveSignedLinuxV3Marker>,
) -> Result<(), AppCoreError> {
    installed
        .refresh_linux()
        .map_err(|()| AppCoreError::RuntimeUnavailable)?;
    let prepared = installed
        .take_prepared()
        .map_err(|()| AppCoreError::RuntimeUnavailable)?;
    let confirmed = controller
        .run_supervisor(move |supervisor| supervisor.confirm_installed_native_enrollment(prepared))
        .await
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    installed
        .revalidate_confirmed(&confirmed)
        .map_err(|()| AppCoreError::RuntimeUnavailable)?;
    let marker = ActiveSignedLinuxV3Marker::from_confirmed(&confirmed)
        .ok_or(AppCoreError::RuntimeUnavailable)?;
    if previous != Some(marker) {
        return Err(AppCoreError::RuntimeUnavailable);
    }
    linux_v3_latch::persist(&controller.signed_linux_v3_latch_path)
        .map_err(|_| AppCoreError::RuntimeUnavailable)?;
    *controller
        .active_signed_linux_v3
        .lock()
        .map_err(|_| AppCoreError::RuntimeUnavailable)? = Some(marker);
    Ok(())
}

fn ensure_not_stopping(controller: &BundledRuntimeController) -> Result<(), AppCoreError> {
    (!controller.operation_fence.is_stopping())
        .then_some(())
        .ok_or(AppCoreError::RuntimeUnavailable)
}
