//! Signed desktop-host native provider credential enrollment.
//!
//! The TUI runs inside the `runne-desktop` image, so the protected V3
//! Request/Begin/relay transcript and the credential-service session share the
//! exact native identity the installed tuple admits. The hidden terminal buffer
//! hands the secret to the authenticated writer relay directly.

use super::{BackendOwner, TIMEOUT};
use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialOperationStateV2, ProviderCredentialProviderV2,
    ProviderCredentialReadinessV2,
};
use runne_platform_desktop::{
    CredentialWriterHandoffMode, NativeProtectedCredentialEnrollmentBegin,
    ProtectedBundledRuntimeSupervisor, UpdateCoordinator,
};
use runne_secure_store::{
    ProviderCredentialId, ProviderCredentialMaterial, ProviderCredentialMaterialKind,
};
use std::time::Instant;

impl BackendOwner {
    /// Reports whether the signed installed admission is available to this host.
    #[must_use]
    pub(crate) fn enrollment_admission_available(&self) -> bool {
        UpdateCoordinator::for_current_installed_release(&self.runtime_root).is_some()
    }

    /// Runs one authenticated Pair enrollment in the already-owned supervisor.
    ///
    /// # Errors
    ///
    /// Returns a closed, secret-free code for a non-desktop image, missing
    /// signed installation admission, rejected transition, or terminal failure.
    pub async fn enroll_provider(
        &mut self,
        provider: ProviderCredentialId,
        material: ProviderCredentialMaterial,
    ) -> Result<(), String> {
        if !Self::is_desktop_host() {
            return Err("provider credential enrollment requires runne-desktop --chat".to_owned());
        }
        let provider = provider_v2(provider)?;
        if material.kind() != ProviderCredentialMaterialKind::Legacy {
            return Err("unsupported credential material".to_owned());
        }
        let coordinator = UpdateCoordinator::for_current_installed_release(&self.runtime_root)
            .ok_or_else(|| "qualified installed release unavailable".to_owned())?;
        let prepared = coordinator
            .prepare_installed_native_enrollment()
            .map_err(|_| "qualified installed release unavailable".to_owned())?
            .ok_or_else(|| "qualified installed release unavailable".to_owned())?;
        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or_else(|| "protected runtime unavailable".to_owned())?;
        let confirmed = supervisor
            .confirm_installed_native_enrollment(prepared)
            .map_err(|_| "signed installed release admission rejected".to_owned())?;
        supervisor
            .begin_credential_enrollment_transition(&confirmed)
            .map_err(|_| "protected enrollment transition rejected".to_owned())?;
        let profile = supervisor
            .take_runtime_profile()
            .ok_or_else(|| "protected enrollment profile unavailable".to_owned())?;
        let client = profile
            .connect(TIMEOUT)
            .await
            .map_err(|_| "protected enrollment authentication failed".to_owned())?;
        supervisor
            .record_client_ready(&client)
            .map_err(|_| "protected enrollment readiness rejected".to_owned())?;
        self.client = client;
        self.renewed_at = Instant::now();
        let revision = self
            .client
            .provider_credential_status(provider)
            .await
            .map_err(|_| "provider credential status unavailable".to_owned())?
            .lifecycle_revision();
        ensure_credential_service_registered()?;
        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or_else(|| "protected runtime unavailable".to_owned())?;
        let prepared_session = supervisor
            .prepare_credential_service_session_registration(&confirmed)
            .map_err(|_| "credential service session unavailable".to_owned())?;
        let registered = prepared_session
            .register()
            .await
            .map_err(|_| "credential service session unavailable".to_owned())?;
        supervisor
            .confirm_credential_service_session(registered)
            .map_err(|_| "credential service session rejected".to_owned())?;
        complete_pair(supervisor, &confirmed, provider, revision, material)?;
        self.renewed_at = Instant::now();
        let status = self
            .client
            .provider_credential_status(provider)
            .await
            .map_err(|_| "provider credential status unavailable".to_owned())?;
        if status.readiness() == ProviderCredentialReadinessV2::Ready {
            Ok(())
        } else {
            Err("provider credential readiness not confirmed".to_owned())
        }
    }
}

fn complete_pair(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    confirmed: &runne_platform_desktop::ConfirmedInstalledNativeEnrollment,
    provider: ProviderCredentialProviderV2,
    revision: u64,
    material: ProviderCredentialMaterial,
) -> Result<(), String> {
    let intent_session = supervisor
        .current_credential_enrollment_intent_binding()
        .map_err(|_| "protected enrollment session unavailable".to_owned())?;
    let command_id = uuid::Uuid::now_v7().to_string();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        provider,
        revision,
        &command_id,
        &command_id,
        &command_id,
    )
    .map_err(|_| "provider credential enrollment command rejected".to_owned())?;
    let begin = NativeProtectedCredentialEnrollmentBegin::new(
        command,
        native_confirmation(intent_session, provider, revision),
    )
    .map_err(|_| "provider credential enrollment command rejected".to_owned())?;
    let mut enrollment = supervisor
        .begin_protected_credential_enrollment(begin)
        .map_err(|_| "provider credential enrollment begin rejected".to_owned())?;
    let mut handoff = supervisor
        .run_credential_writer_handoff(confirmed, CredentialWriterHandoffMode::Pair)
        .map_err(|_| "provider credential writer handoff rejected".to_owned())?;
    let result = relay_secret(supervisor, &mut enrollment, &mut handoff, material);
    let reaped = handoff
        .reap_exact_writer()
        .map_err(|_| "provider credential writer cleanup failed".to_owned());
    result.and(reaped)
}

fn relay_secret(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    enrollment: &mut runne_platform_desktop::PreparedProtectedCredentialEnrollment,
    handoff: &mut runne_platform_desktop::CredentialWriterHandoff,
    material: ProviderCredentialMaterial,
) -> Result<(), String> {
    supervisor
        .receive_credential_secret_relay(enrollment)
        .map_err(|_| "provider credential relay rejected".to_owned())?;
    let relay = enrollment
        .take_relay()
        .ok_or_else(|| "provider credential relay unavailable".to_owned())?;
    let relay_handle = handoff
        .take_pair_secret_relay()
        .ok_or_else(|| "provider credential relay unavailable".to_owned())?;
    let (_, secret) = material.into_zeroizing();
    relay_handle
        .seal_and_write(&relay, secret)
        .map_err(|_| "provider credential relay rejected".to_owned())?;
    supervisor
        .finish_protected_credential_enrollment(enrollment, &relay)
        .map_err(|_| "provider credential enrollment completion rejected".to_owned())?;
    if enrollment.terminal()
        && enrollment.snapshot().state() == ProviderCredentialOperationStateV2::Completed
    {
        Ok(())
    } else {
        Err("provider credential enrollment did not complete".to_owned())
    }
}

fn provider_v2(id: ProviderCredentialId) -> Result<ProviderCredentialProviderV2, String> {
    match id {
        ProviderCredentialId::OpenAi => Ok(ProviderCredentialProviderV2::OpenAi),
        ProviderCredentialId::DeepSeek => Ok(ProviderCredentialProviderV2::DeepSeek),
        _ => Err("provider credential enrollment unsupported for this provider".to_owned()),
    }
}

fn ensure_credential_service_registered() -> Result<(), String> {
    use runne_macos_xpc::{
        CredentialServiceRegistrationManager, CredentialServiceRegistrationStatus,
    };
    let version = env!("CARGO_PKG_VERSION");
    let manager = CredentialServiceRegistrationManager::new(version, version)
        .map_err(|_| "credential service registration unavailable".to_owned())?;
    match manager.status() {
        CredentialServiceRegistrationStatus::Enabled => Ok(()),
        CredentialServiceRegistrationStatus::NotRegistered => manager
            .register()
            .map_err(|_| "credential service registration rejected".to_owned()),
        CredentialServiceRegistrationStatus::RequiresApproval => {
            Err("credential service requires approval in System Settings".to_owned())
        }
        CredentialServiceRegistrationStatus::NotFound
        | CredentialServiceRegistrationStatus::Unavailable => {
            Err("credential service unavailable".to_owned())
        }
    }
}

fn native_confirmation(
    intent_session: [u8; 32],
    provider: ProviderCredentialProviderV2,
    revision: u64,
) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let label = b"runne-desktop-chat";
    let mut renderer = Sha256::new();
    renderer.update(b"gocode/provider-credential-enrollment/renderer/v1\0");
    renderer.update(u32::try_from(label.len()).unwrap_or(u32::MAX).to_be_bytes());
    renderer.update(label);
    renderer.update(1_u64.to_be_bytes());
    let renderer: [u8; 32] = renderer.finalize().into();
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/provider-credential-enrollment/native-confirmation/v1\0");
    hasher.update(intent_session);
    hasher.update(renderer);
    hasher.update([provider.wire_tag(), 1, 1]);
    hasher.update(revision.to_be_bytes());
    hasher.update([0]);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_confirmation_binds_provider_and_revision() {
        let first = native_confirmation([7; 32], ProviderCredentialProviderV2::DeepSeek, 3);
        let same = native_confirmation([7; 32], ProviderCredentialProviderV2::DeepSeek, 3);
        let other_provider = native_confirmation([7; 32], ProviderCredentialProviderV2::OpenAi, 3);
        let other_revision =
            native_confirmation([7; 32], ProviderCredentialProviderV2::DeepSeek, 4);
        assert_eq!(first, same);
        assert_ne!(first, other_provider);
        assert_ne!(first, other_revision);
        assert_ne!(first, [0; 32]);
    }

    #[test]
    fn provider_mapping_is_closed() {
        assert_eq!(
            provider_v2(ProviderCredentialId::DeepSeek).unwrap(),
            ProviderCredentialProviderV2::DeepSeek
        );
        assert_eq!(
            provider_v2(ProviderCredentialId::OpenAi).unwrap(),
            ProviderCredentialProviderV2::OpenAi
        );
        assert!(provider_v2(ProviderCredentialId::Zai).is_err());
        assert!(provider_v2(ProviderCredentialId::LocalEngine).is_err());
    }
}
