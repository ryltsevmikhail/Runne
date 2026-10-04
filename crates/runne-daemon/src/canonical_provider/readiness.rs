use super::*;
use runne_api::ProviderActivationReadinessV1;
use runne_secure_store::ProviderCredentialId;

pub(super) struct CompositionReadinessInputs {
    pub(super) activation_profile_digest: [u8; 32],
    pub(super) retained_key_backend: bool,
    pub(super) credential_status: ProviderCredentialStatus,
    pub(super) journal_binding: ProviderJournalKeyBinding,
    pub(super) journal_key_status: ProviderJournalKeyStatus,
    pub(super) runtime_authority_id: [u8; 16],
    pub(super) database_generation: u64,
}

/// Typed pre-readiness failures for exact provider composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderReadinessError {
    /// Exact profile artifact or activation binding differs.
    #[error("provider profile binding mismatch")]
    ProfileBinding,
    /// Native backend cannot support credential and retained journal keys.
    #[error("provider runne-secure-store backend unsupported")]
    SecureStoreBackend,
    /// Credential metadata is not exactly configured.
    #[error("provider credential unavailable")]
    Credential,
    /// Active database-bound journal key metadata is absent or mismatched.
    #[error("provider journal key unavailable")]
    JournalKey,
}

/// Non-secret evidence required before provider readiness can be emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReadinessEvidence {
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

impl ProviderReadinessEvidence {
    pub(super) fn for_composition(
        profile: &dyn TextProviderProfile,
        inputs: CompositionReadinessInputs,
    ) -> Self {
        Self {
            profile_id: profile.profile_id().to_owned(),
            profile_digest: profile.profile_digest(),
            activation_profile_id: profile.profile_id().to_owned(),
            activation_profile_digest: inputs.activation_profile_digest,
            retained_key_backend: inputs.retained_key_backend,
            credential_status: inputs.credential_status,
            journal_binding: Some(inputs.journal_binding),
            journal_key_status: inputs.journal_key_status,
            runtime_authority_id: inputs.runtime_authority_id,
            database_generation: inputs.database_generation,
        }
    }

    /// Validates every exact non-secret gate.
    pub fn validate(&self) -> Result<(), ProviderReadinessError> {
        self.validate_control_plane()?;
        if self.credential_status != ProviderCredentialStatus::Configured {
            return Err(ProviderReadinessError::Credential);
        }
        Ok(())
    }

    pub(super) fn validate_control_plane(&self) -> Result<(), ProviderReadinessError> {
        if self.profile_id != self.activation_profile_id
            || self.profile_digest != self.activation_profile_digest
        {
            return Err(ProviderReadinessError::ProfileBinding);
        }
        if !self.retained_key_backend {
            return Err(ProviderReadinessError::SecureStoreBackend);
        }
        let binding = self
            .journal_binding
            .ok_or(ProviderReadinessError::JournalKey)?;
        if self.journal_key_status != ProviderJournalKeyStatus::Available
            || binding.runtime_authority_id() != self.runtime_authority_id
            || binding.database_generation() != self.database_generation
        {
            return Err(ProviderReadinessError::JournalKey);
        }
        Ok(())
    }
}

/// Computes metadata-only provider readiness without loading credential
/// material. No credential bytes, keychain errors, or filesystem paths enter
/// the returned disposition.
pub(crate) async fn probe_provider_readiness(
    runtime_authority_id: [u8; 16],
    credential_id: ProviderCredentialId,
) -> ProviderActivationReadinessV1 {
    let keyring = native_journal_keyring(runtime_authority_id);
    if !keyring.retains_multiple_provider_journal_keys() {
        return ProviderActivationReadinessV1::SecureStoreUnavailable;
    }
    match credential_access_policy(credential_id) {
        Ok(_) => {}
        Err(_) => return ProviderActivationReadinessV1::CredentialIdentityMismatch,
    }
    ProviderActivationReadinessV1::CredentialMissing
}

pub(crate) fn credential_access_policy(
    _credential_id: ProviderCredentialId,
) -> Result<ProviderCredentialAccessPolicy, DaemonError> {
    native_credential_access_policy()
}

pub(crate) fn native_credential_access_policy()
-> Result<ProviderCredentialAccessPolicy, DaemonError> {
    let reader = std::env::current_exe()
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    let reader = std::fs::canonicalize(reader)
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    let writer: PathBuf = reader
        .parent()
        .map(|directory| directory.join("runne"))
        .ok_or_else(|| DaemonError::Bootstrap("provider credential identity unavailable".into()))?;
    ProviderCredentialAccessPolicy::new(&writer, &reader)
        .map_err(|_| DaemonError::Bootstrap("provider credential identity unavailable".into()))
}

#[cfg(target_os = "macos")]
pub(super) fn native_journal_keyring(authority: [u8; 16]) -> Arc<dyn ProviderJournalKeyring> {
    Arc::new(runne_secure_store::MacOsKeychainStore::new(hex::encode(
        authority,
    )))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) fn native_journal_keyring(authority: [u8; 16]) -> Arc<dyn ProviderJournalKeyring> {
    Arc::new(runne_secure_store::NativeKeyringStore::with_profile_id(
        hex::encode(authority),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(super) fn native_journal_keyring(_authority: [u8; 16]) -> Arc<dyn ProviderJournalKeyring> {
    Arc::new(runne_secure_store::StubStore::new())
}

#[cfg(target_os = "macos")]
pub(super) fn native_withheld_tail_store(authority: [u8; 16]) -> Arc<NativeWithheldTailStore> {
    Arc::new(runne_secure_store::MacOsKeychainStore::new(hex::encode(
        authority,
    )))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) fn native_withheld_tail_store(authority: [u8; 16]) -> Arc<NativeWithheldTailStore> {
    Arc::new(runne_secure_store::NativeKeyringStore::with_profile_id(
        hex::encode(authority),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(super) fn native_withheld_tail_store(_authority: [u8; 16]) -> Arc<NativeWithheldTailStore> {
    Arc::new(runne_secure_store::StubStore::new())
}
