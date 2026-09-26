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

pub(super) fn diagnostic(stage: &'static str) {
    eprintln!("runne-linux-startup stage={stage}");
}

fn failed<E>(stage: &'static str, _error: E) -> AppCoreError {
    diagnostic(stage);
    AppCoreError::RuntimeUnavailable
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

fn confirmed_v3_successor(
    previous: &runne_platform_desktop::ConfirmedInstalledNativeEnrollment,
    current: &runne_platform_desktop::ConfirmedInstalledNativeEnrollment,
) -> bool {
    let (Some(previous), Some(current)) = (
        previous.enrollment_transition_facts(),
        current.enrollment_transition_facts(),
    ) else {
        return false;
    };
    transition_facts_are_v3_successor(previous, current)
}

fn transition_facts_are_v3_successor(
    previous: runne_platform_desktop::EnrollmentTransitionFacts,
    current: runne_platform_desktop::EnrollmentTransitionFacts,
) -> bool {
    previous.release_tuple_digest == current.release_tuple_digest
        && previous.qualification_binding_digest == current.qualification_binding_digest
        && previous.supervisor_generation.checked_add(1) == Some(current.supervisor_generation)
}

pub(super) async fn transition_and_install(
    controller: &BundledRuntimeController,
    lease: runne_app_core::BundledRuntimeActivationLease,
    mut installed: crate::updater_status::enrollment::NativeInstalledEnrollmentLease,
) -> Result<RuntimeAvailability, AppCoreError> {
    // Authenticate V2 so the supervisor can confirm the signed tuple. This
    // client stays host-local and is never installed into AppCore.
    connect_and_record_ready(controller).await?;
    ensure_not_stopping(controller).map_err(|error| failed("v2_stop_check", error))?;
    installed
        .refresh_linux()
        .map_err(|error| failed("refresh_installed", error))?;
    let prepared = installed
        .take_prepared()
        .map_err(|error| failed("take_prepared", error))?;
    let confirmed = controller
        .run_supervisor(move |supervisor| supervisor.confirm_installed_native_enrollment(prepared))
        .await
        .map_err(|error| failed("confirm_tuple", error))?;
    installed
        .revalidate_confirmed(&confirmed)
        .map_err(|error| failed("revalidate_tuple", error))?;

    let latch_path = controller.signed_linux_v3_latch_path.clone();
    let app = controller
        .startup_app
        .lock()
        .map_err(|error| failed("resource_path", error))?
        .clone()
        .ok_or_else(|| failed("resource_path", ()))?;
    let hint = app
        .path()
        .resource_dir()
        .map_err(|error| failed("resource_path", error))?
        .to_str()
        .ok_or_else(|| failed("resource_path", ()))?
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
        .map_err(|error| failed("persist_transition", error))?;

    let profile = controller
        .supervisor
        .lock()
        .map_err(|error| failed("v3_profile", error))?
        .take_runtime_profile()
        .ok_or_else(|| failed("v3_profile", ()))?;
    let v3 = profile
        .connect(super::BUNDLED_CLIENT_CONNECT_TIMEOUT)
        .await
        .map_err(|error| failed("v3_connect", error))?;
    let readiness = v3.clone();
    controller
        .run_supervisor(move |supervisor| supervisor.record_client_ready(&readiness))
        .await
        .map_err(|error| failed("v3_ready", error))?;
    ensure_not_stopping(controller).map_err(|error| failed("v3_stop_check", error))?;
    installed
        .revalidate_confirmed(&confirmed)
        .map_err(|error| failed("final_revalidate", error))?;
    // The transition rotates the V2 session into V3 and advances the launch
    // generation. Reconfirm against that Ready V3 identity before minting the
    // host-only marker, under the same retained updater operation lease.
    installed
        .refresh_linux()
        .map_err(|error| failed("v3_confirm_refresh", error))?;
    let v3_prepared = installed
        .take_prepared()
        .map_err(|error| failed("v3_confirm_take", error))?;
    let v3_confirmed = controller
        .run_supervisor(move |supervisor| supervisor.confirm_installed_native_enrollment(v3_prepared))
        .await
        .map_err(|error| failed("v3_confirm_tuple", error))?;
    installed
        .revalidate_confirmed(&v3_confirmed)
        .map_err(|error| failed("v3_confirm_revalidate", error))?;
    if !confirmed_v3_successor(&confirmed, &v3_confirmed) {
        diagnostic("v3_confirm_mismatch");
        return Err(AppCoreError::RuntimeUnavailable);
    }
    let marker = ActiveSignedLinuxV3Marker::from_confirmed(&v3_confirmed)
        .ok_or_else(|| failed("confirmed_marker", ()))?;
    *controller
        .active_signed_linux_v3
        .lock()
        .map_err(|error| failed("marker_store", error))? = Some(marker);
    controller.arm_renewal_schedule()?;
    controller
        .core
        .install_bundled_runtime_client(lease, v3)
        .await
        .map_err(|error| failed("install_client", error))?;
    Ok(RuntimeAvailability::Live)
}

async fn connect_and_record_ready(
    controller: &BundledRuntimeController,
) -> Result<(), AppCoreError> {
    let profile = controller
        .supervisor
        .lock()
        .map_err(|error| failed("v2_profile", error))?
        .take_runtime_profile()
        .ok_or_else(|| failed("v2_profile", ()))?;
    let client = profile
        .connect(super::BUNDLED_CLIENT_CONNECT_TIMEOUT)
        .await
        .map_err(|error| failed("v2_connect", error))?;
    let readiness = client.clone();
    controller
        .run_supervisor(move |supervisor| supervisor.record_client_ready(&readiness))
        .await
        .map_err(|error| failed("v2_ready", error))?;
    Ok(())
}

pub(super) async fn confirm_current_marker(
    controller: &BundledRuntimeController,
    installed: &mut crate::updater_status::enrollment::NativeInstalledEnrollmentLease,
    previous: Option<ActiveSignedLinuxV3Marker>,
) -> Result<(), AppCoreError> {
    installed
        .refresh_linux()
        .map_err(|error| failed("verify_refresh", error))?;
    let prepared = installed
        .take_prepared()
        .map_err(|error| failed("verify_take_prepared", error))?;
    let confirmed = controller
        .run_supervisor(move |supervisor| supervisor.confirm_installed_native_enrollment(prepared))
        .await
        .map_err(|error| failed("verify_confirm_tuple", error))?;
    installed
        .revalidate_confirmed(&confirmed)
        .map_err(|error| failed("verify_revalidate", error))?;
    let marker = ActiveSignedLinuxV3Marker::from_confirmed(&confirmed)
        .ok_or_else(|| failed("verify_marker", ()))?;
    if previous != Some(marker) {
        diagnostic("verify_marker_mismatch");
        return Err(AppCoreError::RuntimeUnavailable);
    }
    linux_v3_latch::persist(&controller.signed_linux_v3_latch_path)
        .map_err(|error| failed("verify_latch_persist", error))?;
    *controller
        .active_signed_linux_v3
        .lock()
        .map_err(|error| failed("verify_marker_store", error))? = Some(marker);
    Ok(())
}

fn ensure_not_stopping(controller: &BundledRuntimeController) -> Result<(), AppCoreError> {
    (!controller.operation_fence.is_stopping())
        .then_some(())
        .ok_or(AppCoreError::RuntimeUnavailable)
}

#[cfg(test)]
mod transition_tests {
    use super::transition_facts_are_v3_successor;
    use runne_platform_desktop::EnrollmentTransitionFacts;

    fn facts(release: u8, qualification: u8, generation: u64) -> EnrollmentTransitionFacts {
        EnrollmentTransitionFacts {
            release_tuple_digest: [release; 32],
            qualification_binding_digest: [qualification; 32],
            supervisor_generation: generation,
        }
    }

    #[test]
    fn v3_marker_uses_next_generation_of_same_signed_tuple() {
        assert!(transition_facts_are_v3_successor(facts(1, 2, 8), facts(1, 2, 9)));
        assert!(!transition_facts_are_v3_successor(facts(1, 2, 8), facts(1, 2, 8)));
        assert!(!transition_facts_are_v3_successor(facts(1, 2, 8), facts(1, 2, 10)));
        assert!(!transition_facts_are_v3_successor(facts(1, 2, 8), facts(3, 2, 9)));
        assert!(!transition_facts_are_v3_successor(facts(1, 2, 8), facts(1, 4, 9)));
    }
}
