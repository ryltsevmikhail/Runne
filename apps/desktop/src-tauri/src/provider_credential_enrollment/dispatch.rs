#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
//! Trusted native dispatch chain for one focused credential intent.
//!
//! The renderer only ever sees the closed [`CredentialIntentProjection`]. The
//! secret material, the retained installed admission, the runtime lease, and
//! the daemon dispatch stay on this side of the boundary and fail closed.

use crate::RuntimeLifecycleManager;
use crate::provider_credential_enrollment::{CredentialIntentProjection, CredentialIntentRegistry};
use crate::updater_status::UpdateStatusStore;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_platform_desktop::SecureCredentialPromptDisposition;
use tauri::{AppHandle, Manager as _, WebviewWindow};

use super::CredentialIntentIpc;
#[path = "dispatch/post_fence.rs"]
pub(super) mod post_fence;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::host_prompt::MacOsHostCredentialPrompt;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::prepared::{NativeEnrollmentConfirmation, PreparedCredentialEnrollmentExchange};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use post_fence::PostFenceEnrollmentDependencies;
use post_fence::{run_post_fence_branches, spawn_pre_fence_enrollment_owner};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const NATIVE_PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

type DispatchError = &'static str;

/// Runs the full trusted chain: leases, native prompt, exact daemon
/// confirmation, V3 transition with writer handoff, then the native-only
/// exchange retention. Every failure is a closed, renderer-actionable code.
///
/// The operation and updater fences are deliberately held for the whole flow.
pub async fn dispatch_credential_intent(
    app: &AppHandle,
    window: WebviewWindow,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    intents: &CredentialIntentRegistry,
    request: CredentialIntentIpc,
) -> Result<CredentialIntentProjection, DispatchError> {
    Box::pin(dispatch_inner(
        app, window, lifecycle, updater, intents, request,
    ))
    .await
    .or_else(|error| match error {
        DispatchFailure::Cancelled => Ok(CredentialIntentProjection::Cancelled),
        DispatchFailure::Closed(code) => Err(code),
    })
}

pub(super) enum DispatchFailure {
    Cancelled,
    Closed(DispatchError),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::significant_drop_tightening)]
async fn dispatch_inner(
    app: &AppHandle,
    window: WebviewWindow,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    intents: &CredentialIntentRegistry,
    request: CredentialIntentIpc,
) -> Result<CredentialIntentProjection, DispatchFailure> {
    let work = run_after_action_gate(request, || {
        dispatch_enrollment_inner(app, window, lifecycle, updater, intents, request)
    })?;
    Box::pin(work).await
}

pub(super) fn run_after_action_gate<T>(
    request: CredentialIntentIpc,
    work: impl FnOnce() -> T,
) -> Result<T, DispatchFailure> {
    (request.valid() && request.supported_enrollment_action())
        .then(work)
        .ok_or(DispatchFailure::Closed(
            "provider_credential_action_unsupported",
        ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct LivePostFenceAdmission<'a> {
    intents: &'a CredentialIntentRegistry,
    disposition: SecureCredentialPromptDisposition,
    window: String,
    request: CredentialIntentIpc,
    installed: runne_platform_desktop::ConfirmedInstalledNativeEnrollment,
    runtime: crate::bundled_runtime::NativeCredentialEnrollmentLease,
    updater: crate::updater_status::enrollment::NativeInstalledEnrollmentLease,
    intent_session: Option<[u8; 32]>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PostFenceEnrollmentDependencies for LivePostFenceAdmission<'_> {
    type Output = PreparedCredentialEnrollmentExchange;
    type Error = DispatchFailure;

    fn require_rotated_session(&mut self) -> Result<(), Self::Error> {
        self.intent_session = Some(
            self.runtime
                .rotated_intent_session_binding()
                .map_err(|_| DispatchFailure::Closed("provider_credential_handoff_failed"))?,
        );
        Ok(())
    }

    fn revalidate_updater(&mut self) -> Result<(), Self::Error> {
        self.updater
            .revalidate_confirmed(&self.installed)
            .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))
    }

    fn admit_registry(self) -> Result<Self::Output, Self::Error> {
        PreparedCredentialEnrollmentExchange::from_post_fence_admission(
            self.intents,
            self.disposition,
            NativeEnrollmentConfirmation {
                window: self.window,
                request: self.request,
                installed: self.installed,
                runtime_lease: self.runtime,
                updater_lease: self.updater,
                intent_session: self.intent_session.ok_or(DispatchFailure::Closed(
                    "provider_credential_handoff_failed",
                ))?,
                now: std::time::Instant::now(),
            },
        )
        .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::significant_drop_tightening)]
async fn dispatch_enrollment_inner(
    app: &AppHandle,
    window: WebviewWindow,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    intents: &CredentialIntentRegistry,
    request: CredentialIntentIpc,
) -> Result<CredentialIntentProjection, DispatchFailure> {
    use runne_platform_desktop::SecureCredentialPromptPort as _;

    // Prompt-time leases: runtime operation fence and retained updater fence.
    let mut updater_lease = updater
        .prepare_installed_native_enrollment()
        .await
        .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))?
        .ok_or(DispatchFailure::Closed(
            "provider_credential_enrollment_unavailable",
        ))?;
    let runtime_lease = lifecycle
        .acquire_credential_enrollment_lease()
        .await
        .map_err(|_: crate::AppCoreError| {
            DispatchFailure::Closed("provider_credential_runtime_unavailable")
        })?;

    // Native sheet on a worker thread; the renderer never observes material.
    let prompt_request = request
        .prompt_request()
        .map_err(|()| DispatchFailure::Closed("provider_credential_intent_rejected"))?;
    let window_label = window.label().to_string();
    let mut prompt = MacOsHostCredentialPrompt::new(window, NATIVE_PROMPT_TIMEOUT)
        .map_err(|_| DispatchFailure::Closed("provider_credential_prompt_unavailable"))?;
    let disposition = tauri::async_runtime::spawn_blocking(move || prompt.prompt(prompt_request))
        .await
        .map_err(|_: tauri::Error| {
            DispatchFailure::Closed("provider_credential_prompt_unavailable")
        })?
        .map_err(|_: runne_platform_desktop::SecureCredentialPromptError| {
            DispatchFailure::Closed("provider_credential_prompt_unavailable")
        })?;
    if matches!(disposition, SecureCredentialPromptDisposition::Cancelled) {
        return Err(DispatchFailure::Cancelled);
    }

    // Confirm the retained installed admission against the exact live daemon.
    let prepared = updater_lease
        .take_prepared()
        .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let confirmed = runtime_lease
        .confirm(prepared)
        .await
        .map_err(|_: crate::AppCoreError| {
            DispatchFailure::Closed("provider_credential_unavailable")
        })?;
    updater_lease
        .revalidate_confirmed(&confirmed)
        .map_err(|()| DispatchFailure::Closed("provider_credential_unavailable"))?;

    // Fence the V2 AppCore generation, transition to V3, and install the
    // rotated authenticated client before durable Begin or writer spawn.
    let cleanup = runtime_lease.cleanup_handle();
    let writer_reapers = runtime_lease.writer_reaper_registry();
    let intents = intents.clone();
    let owner_intents = intents.clone();
    let work_reapers = writer_reapers;
    let qualification_app = app.clone();
    let (result, _owner_completion) = spawn_pre_fence_enrollment_owner(
        move || async move {
            let confirmed = runtime_lease
                .transition_and_install(confirmed)
                .await
                .map_err(|_| DispatchFailure::Closed("provider_credential_handoff_failed"))?;
            runtime_lease
                .register_credential_service_session(&confirmed)
                .await
                .map_err(|_| DispatchFailure::Closed("provider_credential_service_unavailable"))?;
            let mut exchange = run_post_fence_branches(LivePostFenceAdmission {
                intents: &owner_intents,
                disposition,
                window: window_label,
                request,
                installed: confirmed,
                runtime: runtime_lease,
                updater: updater_lease,
                intent_session: None,
            })?;
            let qualification_admission = qualification_app
                .state::<crate::bundled_runtime::qualification_ticket::QualificationAdmissionHostState>(
                )
                .take_pending_for_relay()
                .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
            exchange.retain_qualification_admission(qualification_admission);
            let recovery = tauri::async_runtime::spawn_blocking(move || {
                exchange.run(&owner_intents, work_reapers)
            })
            .await
            .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?
            .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
            recovery
                .finish_cleanup()
                .await
                .map_err(|_| DispatchFailure::Closed("provider_credential_cleanup_incomplete"))
        },
        move || async move { cleanup.abort().await },
        || DispatchFailure::Closed("provider_credential_exchange_rejected"),
    )?;
    result
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))??;
    Ok(CredentialIntentProjection::Completed)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[allow(clippy::unused_async)]
async fn dispatch_inner(
    _app: &AppHandle,
    _window: WebviewWindow,
    _lifecycle: &RuntimeLifecycleManager,
    _updater: &UpdateStatusStore,
    _intents: &CredentialIntentRegistry,
    _request: CredentialIntentIpc,
) -> Result<CredentialIntentProjection, DispatchFailure> {
    Err(DispatchFailure::Closed("provider_credential_unsupported"))
}

#[cfg(test)]
#[path = "dispatch/platform_enrollment_scope_tests.rs"]
mod platform_enrollment_scope_tests;
#[cfg(test)]
#[path = "dispatch/round2_tests.rs"]
mod round2_tests;
#[cfg(test)]
#[path = "dispatch/round3_surface_tests.rs"]
mod round3_surface_tests;
#[cfg(test)]
#[path = "dispatch/round3_tests.rs"]
mod round3_tests;
#[cfg(test)]
#[path = "dispatch/round4_watcher_tests.rs"]
mod round4_watcher_tests;
#[cfg(test)]
#[path = "dispatch/round5_watcher_tests.rs"]
mod round5_watcher_tests;
