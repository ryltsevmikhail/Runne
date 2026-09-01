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
use runne_platform_desktop::SecureCredentialPromptDisposition;
use tauri::{AppHandle, WebviewWindow};

use super::CredentialIntentIpc;
#[path = "dispatch/post_fence.rs"]
mod post_fence;
#[cfg(target_os = "macos")]
use super::host_prompt::MacOsHostCredentialPrompt;
#[cfg(target_os = "macos")]
use super::prepared::{NativeEnrollmentConfirmation, PreparedCredentialEnrollmentExchange};
use post_fence::{
    PostFenceEnrollmentDependencies, run_post_fence_branches, spawn_pre_fence_enrollment_owner,
};

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

#[cfg(target_os = "macos")]
#[allow(clippy::significant_drop_tightening)]
async fn dispatch_inner(
    app: &AppHandle,
    window: WebviewWindow,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    intents: &CredentialIntentRegistry,
    request: CredentialIntentIpc,
) -> Result<CredentialIntentProjection, DispatchFailure> {
    let work = run_after_pair_gate(request, || {
        dispatch_pair_inner(app, window, lifecycle, updater, intents, request)
    })?;
    Box::pin(work).await
}

pub(super) fn run_after_pair_gate<T>(
    request: CredentialIntentIpc,
    work: impl FnOnce() -> T,
) -> Result<T, DispatchFailure> {
    request
        .supported_d1_1a()
        .then(work)
        .ok_or(DispatchFailure::Closed(
            "provider_credential_action_unsupported",
        ))
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
#[allow(clippy::significant_drop_tightening)]
async fn dispatch_pair_inner(
    _app: &AppHandle,
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
    let intents = intents.clone();
    let owner_intents = intents.clone();
    let (result, _owner_completion) = spawn_pre_fence_enrollment_owner(
        move || async move {
            let confirmed = runtime_lease
                .transition_and_install(confirmed)
                .await
                .map_err(|_| DispatchFailure::Closed("provider_credential_handoff_failed"))?;
            let exchange = run_post_fence_branches(LivePostFenceAdmission {
                intents: &owner_intents,
                disposition,
                window: window_label,
                request,
                installed: confirmed,
                runtime: runtime_lease,
                updater: updater_lease,
                intent_session: None,
            })?;
            tauri::async_runtime::spawn_blocking(move || exchange.run(&owner_intents))
                .await
                .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?
                .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))
        },
        move || async move { cleanup.abort().await },
    );
    result
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))??;
    Ok(CredentialIntentProjection::Completed)
}

#[cfg(not(target_os = "macos"))]
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
#[path = "dispatch/round2_tests.rs"]
mod round2_tests;
#[cfg(test)]
#[path = "dispatch/round3_surface_tests.rs"]
mod round3_surface_tests;
#[cfg(test)]
#[path = "dispatch/round3_tests.rs"]
mod round3_tests;
