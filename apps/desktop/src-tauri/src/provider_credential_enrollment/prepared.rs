#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code, unused_imports)
)]
use super::intent::{CredentialIntentError, NativeCredentialIntent};
use super::{CredentialIntentAction, CredentialIntentIpc, CredentialIntentRegistry};
use crate::bundled_runtime::NativeCredentialEnrollmentLease;
use crate::updater_status::enrollment::NativeInstalledEnrollmentLease;
use runne_api::{ProviderCredentialProviderV2, ProviderCredentialVerificationKindV2};
use runne_native_qualification::PendingQualificationAdmission;
use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, SecureCredentialMaterial, SecureCredentialPromptDisposition,
};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::time::Instant;
pub mod reap_guard;
#[cfg(test)]
#[path = "prepared/reap_guard_tests.rs"]
mod reap_guard_tests;
pub mod reaper_registry;
#[cfg(test)]
#[path = "prepared/reaper_registry_tests.rs"]
mod reaper_registry_tests;
mod recovery;
mod runner;
pub async fn reconcile_startup(
    lifecycle: &crate::RuntimeLifecycleManager,
    updates: &crate::UpdateStatusStore,
) -> Result<(), ()> {
    recovery::startup::reconcile(lifecycle, updates).await
}
pub use reaper_registry::{
    CredentialWriterReaperLastError, CredentialWriterReaperSnapshot, CredentialWriterReaperState,
};
pub use runner::ProtectedWriterReaperRegistry;
/// Opaque native-only exchange retained for the later daemon control slice.
///
/// This value is deliberately neither serializable nor cloneable and exposes no
/// credential or control-frame surface.
pub(super) struct PreparedCredentialEnrollmentExchange {
    window: String,
    request: CredentialIntentIpc,
    resources: std::sync::Arc<recovery::RecoveryResources>,
    intent: Option<NativeCredentialIntent>,
    intent_session: [u8; 32],
    _expires: Instant,
    material: Option<SecureCredentialMaterial>,
    _renderer_binding: [u8; 32],
    native_confirmation: [u8; 32],
    qualification_admission: Option<Box<PendingQualificationAdmission>>,
}
/// Trusted native inputs retained outside the renderer boundary.
pub(super) struct NativeEnrollmentConfirmation {
    pub(super) window: String,
    pub(super) request: CredentialIntentIpc,
    pub(super) installed: ConfirmedInstalledNativeEnrollment,
    pub(super) runtime_lease: NativeCredentialEnrollmentLease,
    pub(super) updater_lease: NativeInstalledEnrollmentLease,
    pub(super) intent_session: [u8; 32],
    pub(super) now: Instant,
}
impl PreparedCredentialEnrollmentExchange {
    pub(super) fn from_post_fence_admission(
        registry: &CredentialIntentRegistry,
        disposition: SecureCredentialPromptDisposition,
        confirmation: NativeEnrollmentConfirmation,
    ) -> Result<Self, PreparedCredentialEnrollmentError> {
        if confirmation.window.is_empty() || !confirmation.request.valid() {
            return Err(PreparedCredentialEnrollmentError);
        }
        let (material, disposition_tag) =
            accepted_disposition(confirmation.request.action, disposition)?;
        let intent_session = confirmation.intent_session;
        let intent = issue_pending_intent(
            registry,
            &confirmation.window,
            confirmation.request,
            intent_session,
            confirmation.now,
        )?;
        let expires = intent.expires_at();
        let renderer_binding = renderer_binding_digest(
            &confirmation.window,
            confirmation.request.renderer_generation,
        );
        let native_confirmation = native_confirmation_digest(
            confirmation.request,
            intent_session,
            renderer_binding,
            disposition_tag,
        );
        Ok(Self {
            window: confirmation.window,
            request: confirmation.request,
            resources: std::sync::Arc::new(recovery::RecoveryResources {
                runtime: std::sync::Arc::new(confirmation.runtime_lease),
                updater: std::sync::Arc::new(confirmation.updater_lease),
                installed: confirmation.installed,
            }),
            intent: Some(intent),
            intent_session,
            _expires: expires,
            material,
            _renderer_binding: renderer_binding,
            native_confirmation,
            qualification_admission: None,
        })
    }

    pub(super) fn retain_qualification_admission(
        &mut self,
        pending: Option<PendingQualificationAdmission>,
    ) {
        self.qualification_admission = pending.map(Box::new);
    }
}

fn begin_protected_with_qualification(
    supervisor: &std::sync::Arc<
        std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>,
    >,
    begin: runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin,
    pending: Option<PendingQualificationAdmission>,
) -> Result<
    runne_platform_desktop::PreparedProtectedCredentialEnrollment,
    PreparedCredentialEnrollmentError,
> {
    supervisor
        .lock()
        .map_err(|_| PreparedCredentialEnrollmentError)?
        .begin_protected_credential_enrollment_with_qualification(begin, pending)
        .map_err(|_| PreparedCredentialEnrollmentError)
}

fn issue_pending_intent(
    registry: &CredentialIntentRegistry,
    window: &str,
    request: CredentialIntentIpc,
    intent_session: [u8; 32],
    now: Instant,
) -> Result<NativeCredentialIntent, PreparedCredentialEnrollmentError> {
    registry
        .issue(
            window,
            request.renderer_generation,
            request,
            intent_session,
            now,
        )
        .map_err(Into::into)
}

impl fmt::Debug for PreparedCredentialEnrollmentExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedCredentialEnrollmentExchange(<native-only-redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct PreparedCredentialEnrollmentError;

impl From<CredentialIntentError> for PreparedCredentialEnrollmentError {
    fn from(_: CredentialIntentError) -> Self {
        Self
    }
}

fn accepted_disposition(
    action: CredentialIntentAction,
    disposition: SecureCredentialPromptDisposition,
) -> Result<(Option<SecureCredentialMaterial>, u8), PreparedCredentialEnrollmentError> {
    match (action, disposition) {
        (CredentialIntentAction::Pair, SecureCredentialPromptDisposition::Submitted(material)) => {
            Ok((Some(material), 1))
        }
        (
            CredentialIntentAction::Revoke | CredentialIntentAction::MigrateLegacy,
            SecureCredentialPromptDisposition::Confirmed,
        ) => Ok((None, 2)),
        (CredentialIntentAction::Verify, SecureCredentialPromptDisposition::Confirmed) => {
            Ok((None, 3))
        }
        _ => Err(PreparedCredentialEnrollmentError),
    }
}

fn renderer_binding_digest(window: &str, generation: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/provider-credential-enrollment/renderer/v1\0");
    hash_framed(&mut hasher, window.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.finalize().into()
}

fn native_confirmation_digest(
    request: CredentialIntentIpc,
    intent_session: [u8; 32],
    renderer_binding: [u8; 32],
    disposition_tag: u8,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/provider-credential-enrollment/native-confirmation/v1\0");
    hasher.update(intent_session);
    hasher.update(renderer_binding);
    hasher.update([
        provider_tag(request.provider),
        action_tag(request.action),
        disposition_tag,
    ]);
    hasher.update(request.expected_revision.to_be_bytes());
    hasher.update([verification_tag(request.verification_kind)]);
    hasher.finalize().into()
}

fn hash_framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    hasher.update(value);
}

const fn provider_tag(provider: ProviderCredentialProviderV2) -> u8 {
    provider.wire_tag()
}

const fn action_tag(action: CredentialIntentAction) -> u8 {
    match action {
        CredentialIntentAction::Pair => 1,
        CredentialIntentAction::Revoke => 2,
        CredentialIntentAction::MigrateLegacy => 3,
        CredentialIntentAction::Verify => 4,
    }
}

const fn verification_tag(kind: Option<ProviderCredentialVerificationKindV2>) -> u8 {
    match kind {
        None => 0,
        Some(ProviderCredentialVerificationKindV2::Local) => 1,
        Some(ProviderCredentialVerificationKindV2::Remote) => 2,
    }
}

#[cfg(test)]
#[path = "prepared/tests.rs"]
mod tests;
