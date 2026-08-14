use super::*;
use gocode_api::ProviderActivationReadinessV1;
use gocode_secure_store::{ProviderCredentialId, SecureStoreError};

/// Typed pre-readiness failures for exact OpenAI composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenAiReadinessError {
    /// Exact profile artifact or activation binding differs.
    #[error("provider profile binding mismatch")]
    ProfileBinding,
    /// Native backend cannot support credential and retained journal keys.
    #[error("provider secure-store backend unsupported")]
    SecureStoreBackend,
    /// Credential metadata is not exactly configured.
    #[error("provider credential unavailable")]
    Credential,
    /// Active database-bound journal key metadata is absent or mismatched.
    #[error("provider journal key unavailable")]
    JournalKey,
}

/// Non-secret evidence required before OpenAI readiness can be emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiReadinessEvidence {
    /// Parsed exact profile identity.
    pub profile_id: String,
    /// Parsed exact profile digest.
    pub profile_digest: [u8; 32],
    /// Activation-bound profile identity.
    pub activation_profile_id: String,
    /// Activation-bound profile digest.
    pub activation_profile_digest: [u8; 32],
    /// Whether native retained-key support exists.
    pub retained_key_backend: bool,
    /// Credential metadata status only.
    pub credential_status: ProviderCredentialStatus,
    /// Active database key binding, without bytes.
    pub journal_binding: Option<ProviderJournalKeyBinding>,
    /// Native metadata-only key status.
    pub journal_key_status: ProviderJournalKeyStatus,
    /// Expected stable runtime authority.
    pub runtime_authority_id: [u8; 16],
    /// Expected database generation.
    pub database_generation: u64,
}

impl OpenAiReadinessEvidence {
    /// Validates every exact non-secret gate.
    pub fn validate(&self) -> Result<(), OpenAiReadinessError> {
        if self.profile_id != gocode_provider_openai::OPENAI_RESPONSES_PROFILE_ID
            || self.profile_id != self.activation_profile_id
            || self.profile_digest != self.activation_profile_digest
        {
            return Err(OpenAiReadinessError::ProfileBinding);
        }
        if !self.retained_key_backend {
            return Err(OpenAiReadinessError::SecureStoreBackend);
        }
        if self.credential_status != ProviderCredentialStatus::Configured {
            return Err(OpenAiReadinessError::Credential);
        }
        let binding = self
            .journal_binding
            .ok_or(OpenAiReadinessError::JournalKey)?;
        if self.journal_key_status != ProviderJournalKeyStatus::Available
            || binding.runtime_authority_id() != self.runtime_authority_id
            || binding.database_generation() != self.database_generation
        {
            return Err(OpenAiReadinessError::JournalKey);
        }
        Ok(())
    }
}

/// Computes metadata-only provider readiness without loading credential
/// material. No credential bytes, keychain errors, or filesystem paths enter
/// the returned disposition.
pub(crate) async fn probe_provider_readiness(
    runtime_authority_id: [u8; 16],
) -> ProviderActivationReadinessV1 {
    let keyring = native_journal_keyring(runtime_authority_id);
    if !keyring.retains_multiple_provider_journal_keys() {
        return ProviderActivationReadinessV1::SecureStoreUnavailable;
    }
    let access = match credential_access_policy() {
        Ok(access) => access,
        Err(_) => return ProviderActivationReadinessV1::CredentialIdentityMismatch,
    };
    let store: Arc<dyn ProviderCredentialStore> = Arc::new(NativeProviderCredentialStore::new());
    let probe = tokio::task::spawn_blocking(move || {
        store.provider_credential_status(ProviderCredentialId::OpenAi, &access)
    })
    .await;
    match probe {
        Ok(Ok(ProviderCredentialStatus::Configured)) => ProviderActivationReadinessV1::Ready,
        Ok(Ok(ProviderCredentialStatus::Missing)) => {
            ProviderActivationReadinessV1::CredentialMissing
        }
        Ok(Ok(ProviderCredentialStatus::Unsupported)) => {
            ProviderActivationReadinessV1::SecureStoreUnavailable
        }
        Ok(Err(SecureStoreError::CredentialAccessDenied)) => {
            ProviderActivationReadinessV1::CredentialAccessDenied
        }
        Ok(Err(SecureStoreError::CredentialIdentityMismatch)) => {
            ProviderActivationReadinessV1::CredentialIdentityMismatch
        }
        _ => ProviderActivationReadinessV1::SecureStoreUnavailable,
    }
}

pub(super) fn credential_access_policy() -> Result<ProviderCredentialAccessPolicy, DaemonError> {
    let reader = std::env::current_exe()
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    let reader = std::fs::canonicalize(reader)
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    let writer: PathBuf = reader
        .parent()
        .map(|directory| directory.join("gocode"))
        .ok_or_else(|| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    ProviderCredentialAccessPolicy::new(&writer, &reader)
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))
}

#[cfg(target_os = "macos")]
pub(super) fn native_journal_keyring(authority: [u8; 16]) -> Arc<dyn ProviderJournalKeyring> {
    Arc::new(gocode_secure_store::MacOsKeychainStore::new(hex::encode(
        authority,
    )))
}

#[cfg(not(target_os = "macos"))]
pub(super) fn native_journal_keyring(_authority: [u8; 16]) -> Arc<dyn ProviderJournalKeyring> {
    Arc::new(gocode_secure_store::StubStore::new())
}
