use super::super::DispatchFailure;
use crate::provider_credential_enrollment::{
    CredentialIntentAction, CredentialIntentIpc, CredentialIntentRegistry,
};
use runne_api::{BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2};
use runne_platform_desktop::{
    NativeProtectedCredentialEnrollmentBegin, SecureCredentialMaterial,
    SecureCredentialPromptDisposition,
};
use sha2::{Digest as _, Sha256};
use std::sync::Mutex;

pub(super) fn prepare_begin(
    intents: &CredentialIntentRegistry,
    window: &str,
    request: CredentialIntentIpc,
    session: [u8; 32],
    disposition: SecureCredentialPromptDisposition,
) -> Result<
    (
        NativeProtectedCredentialEnrollmentBegin,
        Option<SecureCredentialMaterial>,
    ),
    DispatchFailure,
> {
    let (material, disposition_tag) = accepted_disposition(request.action, disposition)?;
    let intent = intents
        .issue(
            window,
            request.renderer_generation,
            request,
            session,
            std::time::Instant::now(),
        )
        .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
    let renderer = renderer_binding_digest(window, request.renderer_generation);
    let confirmation = native_confirmation_digest(request, session, renderer, disposition_tag);
    let consumed = intents
        .consume(
            intent,
            window,
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
    let begin = NativeProtectedCredentialEnrollmentBegin::new(command, confirmation)
        .map_err(|_| DispatchFailure::Closed("provider_credential_exchange_rejected"))?;
    Ok((begin, material))
}

pub(super) fn accepted_disposition(
    action: CredentialIntentAction,
    disposition: SecureCredentialPromptDisposition,
) -> Result<(Option<SecureCredentialMaterial>, u8), DispatchFailure> {
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

pub(super) fn run_exchange_owner(
    supervisor: &Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>,
    begin: NativeProtectedCredentialEnrollmentBegin,
    material: Option<SecureCredentialMaterial>,
    pair: bool,
) -> Result<(), ()> {
    (|| {
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
            run_pair_exchange(supervisor, &mut enrollment, material)?;
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
    })()
}

fn run_pair_exchange(
    supervisor: &Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>,
    enrollment: &mut runne_platform_desktop::PreparedProtectedCredentialEnrollment,
    material: Option<SecureCredentialMaterial>,
) -> Result<(), ()> {
    let material = material.ok_or(())?;
    let mut guard = supervisor.lock().map_err(|_| ())?;
    guard
        .receive_credential_secret_relay(enrollment)
        .map_err(|_| ())?;
    let relay = guard
        .receive_linux_pair_secret_relay_fd(enrollment)
        .map_err(|_| ())?;
    drop(guard);
    let frame = enrollment.take_relay().ok_or(())?;
    let native_oauth =
        material.kind() == runne_platform_desktop::SecureCredentialMaterialKind::NativeOAuth;
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
        .finish_protected_credential_enrollment(enrollment, &frame)
        .map_err(|_| ())
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

const fn action_tag(action: CredentialIntentAction) -> u8 {
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
