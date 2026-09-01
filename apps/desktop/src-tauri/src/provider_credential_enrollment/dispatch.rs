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
#[cfg(target_os = "macos")]
use super::host_prompt::MacOsHostCredentialPrompt;
#[cfg(target_os = "macos")]
use super::prepared::{NativeEnrollmentConfirmation, PreparedCredentialEnrollmentExchange};

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

enum DispatchFailure {
    Cancelled,
    Closed(DispatchError),
}

#[cfg(target_os = "macos")]
#[allow(clippy::significant_drop_tightening)]
async fn dispatch_inner(
    _app: &AppHandle,
    window: WebviewWindow,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    intents: &CredentialIntentRegistry,
    request: CredentialIntentIpc,
) -> Result<CredentialIntentProjection, DispatchFailure> {
    use runne_platform_desktop::SecureCredentialPromptPort as _;

    if !request.supported_d1_1a() {
        return Err(DispatchFailure::Closed(
            "provider_credential_action_unsupported",
        ));
    }

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
    let confirmed = runtime_lease
        .transition_and_install(confirmed)
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_handoff_failed"))?;
    let Ok(intent_session) = runtime_lease.rotated_intent_session_binding() else {
        runtime_lease.abort_enrollment();
        return Err(DispatchFailure::Closed(
            "provider_credential_handoff_failed",
        ));
    };

    // Retain the native-only exchange; the intent capability expires bound to
    // this exact window, generation, and session if the daemon never sees it.
    let confirmation = NativeEnrollmentConfirmation {
        window: window_label,
        request,
        installed: confirmed,
        runtime_lease,
        updater_lease,
        intent_session,
        now: std::time::Instant::now(),
    };
    let exchange =
        PreparedCredentialEnrollmentExchange::after_prompt(intents, disposition, confirmation)
            .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
    let intents = intents.clone();
    tauri::async_runtime::spawn_blocking(move || exchange.run(&intents))
        .await
        .map_err(|_: tauri::Error| {
            DispatchFailure::Closed("provider_credential_exchange_rejected")
        })?
        .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
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
