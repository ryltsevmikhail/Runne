use super::{DispatchFailure, run_after_action_gate};
use crate::RuntimeLifecycleManager;
use crate::provider_credential_enrollment::{
    CredentialIntentAction, CredentialIntentIpc, CredentialIntentProjection,
    CredentialIntentRegistry,
};
use crate::updater_status::UpdateStatusStore;
use runne_api::{BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2};
use runne_platform_desktop::{SecureCredentialPromptDisposition, SecureCredentialPromptPort as _};
use sha2::{Digest as _, Sha256};
use tauri::{AppHandle, Manager as _, WebviewWindow};

#[allow(clippy::significant_drop_tightening)]
pub(super) async fn dispatch_inner(
    app: &AppHandle,
    window: WebviewWindow,
    lifecycle: &RuntimeLifecycleManager,
    updater: &UpdateStatusStore,
    intents: &CredentialIntentRegistry,
    request: CredentialIntentIpc,
) -> Result<CredentialIntentProjection, DispatchFailure> {
    run_after_action_gate(request, || ())?;
    if !request.supported_enrollment_action() {
        return Err(DispatchFailure::Closed(
            "provider_credential_action_unsupported",
        ));
    }
    let executable = std::env::current_exe()
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let resources = app
        .path()
        .resource_dir()
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let mut updater_lease = updater
        .prepare_linux_installed_native_enrollment(&executable, &resources)
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?
        .ok_or(DispatchFailure::Closed(
            "provider_credential_enrollment_unavailable",
        ))?;
    updater_lease
        .refresh_linux()
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let runtime = lifecycle
        .acquire_credential_enrollment_lease()
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_runtime_unavailable"))?;

    let prompt_request = request
        .prompt_request()
        .map_err(|_| DispatchFailure::Closed("provider_credential_intent_rejected"))?;
    let window_label = window.label().to_string();
    let mut prompt = super::super::host_prompt::LinuxHostCredentialPrompt::new()
        .map_err(|_| DispatchFailure::Closed("provider_credential_prompt_unavailable"))?;
    let disposition = tauri::async_runtime::spawn_blocking(move || prompt.prompt(prompt_request))
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_prompt_unavailable"))?
        .map_err(|_| DispatchFailure::Closed("provider_credential_prompt_unavailable"))?;
    if matches!(disposition, SecureCredentialPromptDisposition::Cancelled) {
        return Ok(CredentialIntentProjection::Cancelled);
    }
    crate::provider_credential_enrollment::linux_activation::enforce_pre_prompt_gate(&request)
        .map_err(|_| DispatchFailure::Closed("activation_gate_closed_after_prompt"))?;
    updater_lease
        .refresh_linux()
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let prepared = updater_lease
        .take_prepared()
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let installed = runtime
        .confirm(prepared)
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    updater_lease
        .revalidate_confirmed(&installed)
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    runtime
        .matches_active_signed_linux_v3(&installed)
        .map_err(|_| DispatchFailure::Closed("provider_credential_enrollment_unavailable"))?;
    runtime
        .prepare_credential_status(installed)
        .await
        .map_err(|_| DispatchFailure::Closed("provider_credential_unavailable"))?;
    let session = runtime
        .rotated_intent_session_binding()
        .map_err(|_| DispatchFailure::Closed("provider_credential_handoff_failed"))?;
    let (material, disposition_tag) = accepted_disposition(request.action, disposition)?;
    let now = std::time::Instant::now();
    let intent = intents
        .issue(
            &window_label,
            request.renderer_generation,
            request,
            session,
            now,
        )
        .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
    let renderer = renderer_binding_digest(&window_label, request.renderer_generation);
    let native_confirmation =
        native_confirmation_digest(request, session, renderer, disposition_tag);
    let consumed = intents
        .consume(
            intent,
            &window_label,
            request.renderer_generation,
            request,
            session,
            std::time::Instant::now(),
        )
        .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
    let command_id = uuid::Uuid::now_v7().to_string();
    let action = match request.action {
        CredentialIntentAction::Pair => ProviderCredentialEnrollmentActionV2::Pair,
        CredentialIntentAction::Revoke => ProviderCredentialEnrollmentActionV2::Revoke,
        _ => {
            return Err(DispatchFailure::Closed(
                "provider_credential_action_unsupported",
            ));
        }
    };
    let command = BeginProviderCredentialEnrollment::new(
        action,
        request.provider,
        request.expected_revision,
        &command_id,
        &command_id,
        consumed.daemon_id(),
    )
    .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
    let begin = runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin::new(
        command,
        native_confirmation,
    )
    .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
    let supervisor = runtime.supervisor_handle();
    let cleanup = runtime.cleanup_handle();
    let pair = request.action == CredentialIntentAction::Pair;
    let task = tauri::async_runtime::spawn_blocking(move || {
        // The native worker owns both fences until terminal readback or abort.
        let _held_fences = (runtime, updater_lease);
        run_exchange_owner(supervisor, begin, material, pair)
    });
    let result = match task.await {
        Ok(result) => result,
        Err(_) => {
            cleanup.abort().await;
            return Err(DispatchFailure::Closed(
                "provider_credential_exchange_failed",
            ));
        }
    };
    if result.is_err() {
        cleanup.abort().await;
        return Err(DispatchFailure::Closed(
            "provider_credential_exchange_failed",
        ));
    }
    Ok(CredentialIntentProjection::Completed)
}

fn run_exchange_owner(
    supervisor: std::sync::Arc<
        std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>,
    >,
    begin: runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin,
    material: Option<runne_platform_desktop::SecureCredentialMaterial>,
    pair: bool,
) -> Result<(), ()> {
    let result = (|| {
        let mut enrollment = supervisor
            .lock()
            .map_err(|_| ())?
            .begin_protected_credential_enrollment(begin)
            .map_err(|_| ())?;
        if enrollment.snapshot().state() != runne_api::ProviderCredentialOperationStateV2::Prepared
        {
            return Err(());
        }
        if pair {
            let material = material.ok_or(())?;
            let mut guard = supervisor.lock().map_err(|_| ())?;
            guard
                .receive_credential_secret_relay(&mut enrollment)
                .map_err(|_| ())?;
            let relay = guard
                .receive_linux_pair_secret_relay_fd(&mut enrollment)
                .map_err(|_| ())?;
            drop(guard);
            let frame = enrollment.take_relay().ok_or(())?;
            let native_oauth = material.kind()
                == runne_platform_desktop::SecureCredentialMaterialKind::NativeOAuth;
            let secret = material.into_pipe_bytes().into_zeroizing();
            if native_oauth {
                relay.seal_and_write_native_oauth(&frame, secret)
            } else {
                relay.seal_and_write(&frame, secret)
            }
            .map_err(|_| ())?;
            supervisor
                .lock()
                .map_err(|_| ())?
                .finish_protected_credential_enrollment(&mut enrollment, &frame)
                .map_err(|_| ())?;
        } else {
            if material.is_some() {
                return Err(());
            }
            supervisor
                .lock()
                .map_err(|_| ())?
                .finish_control_only_credential_enrollment(&mut enrollment)
                .map_err(|_| ())?;
        }
        (enrollment.terminal()
            && enrollment.snapshot().state()
                == runne_api::ProviderCredentialOperationStateV2::Completed)
            .then_some(())
            .ok_or(())
    })();
    result
}

fn accepted_disposition(
    action: CredentialIntentAction,
    disposition: SecureCredentialPromptDisposition,
) -> Result<(Option<runne_platform_desktop::SecureCredentialMaterial>, u8), DispatchFailure> {
    match (action, disposition) {
        (CredentialIntentAction::Pair, SecureCredentialPromptDisposition::Submitted(material)) => {
            Ok((Some(material), 1))
        }
        (CredentialIntentAction::Revoke, SecureCredentialPromptDisposition::Confirmed) => {
            Ok((None, 2))
        }
        _ => Err(DispatchFailure::Closed(
            "provider_credential_intent_rejected",
        )),
    }
}

fn renderer_binding_digest(window: &str, generation: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"gocode/provider-credential-enrollment/renderer/v1\0");
    hash_framed(&mut hash, window.as_bytes());
    hash.update(generation.to_be_bytes());
    hash.finalize().into()
}

fn native_confirmation_digest(
    request: CredentialIntentIpc,
    session: [u8; 32],
    renderer: [u8; 32],
    tag: u8,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"gocode/provider-credential-enrollment/native-confirmation/v1\0");
    hash.update(session);
    hash.update(renderer);
    hash.update([request.provider.wire_tag(), action_tag(request.action), tag]);
    hash.update(request.expected_revision.to_be_bytes());
    hash.update([0]);
    hash.finalize().into()
}

fn action_tag(action: CredentialIntentAction) -> u8 {
    match action {
        CredentialIntentAction::Pair => 1,
        CredentialIntentAction::Revoke => 2,
        CredentialIntentAction::MigrateLegacy => 3,
        CredentialIntentAction::Verify => 4,
    }
}

fn hash_framed(hash: &mut Sha256, value: &[u8]) {
    hash.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    hash.update(value);
}
