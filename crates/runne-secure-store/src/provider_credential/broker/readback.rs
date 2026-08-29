use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget,
    CredentialDispatchCapability, CredentialOperationAction, CredentialVerificationCapability,
    CredentialVersionRef,
};

use super::errors::BrokerError;
use super::readback_observation::{
    legacy_import_observation, legacy_observation, version_observation,
};
use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, ProviderCredentialStatus, ProviderCredentialStore,
    SecureStoreError,
};

pub trait ProviderCredentialReadback: Send + Sync {
    /// Reads metadata for one exact immutable version.
    ///
    /// # Errors
    ///
    /// Returns a closed access, missing, corruption, or backend error.
    fn readback_exact_version(
        &self,
        input: ExactVersionReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError>;

    /// Proves absence of one exact version or the legacy source.
    ///
    /// # Errors
    ///
    /// Returns a closed access, conflict, corruption, or backend error.
    fn readback_exact_absence(
        &self,
        input: ExactAbsenceReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError>;
}

pub trait ProviderCredentialDispatchMaterializer: Send + Sync {
    /// Materializes only the version named by a current dispatch capability.
    ///
    /// # Errors
    ///
    /// Returns a closed stale-capability, access, missing, or backend error.
    fn materialize_active(
        &self,
        capability: &CredentialDispatchCapability,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;
}

pub trait ProviderCredentialVerificationMaterializer: Send + Sync {
    /// Materializes only the version named by a current verification capability.
    ///
    /// # Errors
    ///
    /// Returns a closed stale-capability, access, missing, or backend error.
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;
}

pub struct ExactVersionReadback {
    command: CredentialBrokerCommand,
    reference: CredentialVersionRef,
}

pub struct ExactAbsenceReadback {
    command: CredentialBrokerCommand,
    reference: Option<CredentialVersionRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialReadbackObservation {
    pub(super) binding: CredentialBindingDigest,
    pub(super) present: bool,
}

impl CredentialReadbackObservation {
    #[must_use]
    pub const fn binding(&self) -> CredentialBindingDigest {
        self.binding
    }

    #[must_use]
    pub const fn present(&self) -> bool {
        self.present
    }
}

impl ExactVersionReadback {
    /// Validates and captures an exact create/import readback command.
    ///
    /// # Errors
    ///
    /// Returns access denied for any other action or target shape.
    pub fn new(command: CredentialBrokerCommand) -> Result<Self, SecureStoreError> {
        let reference = match (command.action(), command.target()) {
            (CredentialOperationAction::Pair, CredentialBrokerTarget::Version(reference))
            | (
                CredentialOperationAction::MigrateLegacy,
                CredentialBrokerTarget::LegacyImport(reference),
            ) => reference.clone(),
            _ => return Err(BrokerError::AccessDenied.into()),
        };
        Ok(Self { command, reference })
    }
}

impl ExactAbsenceReadback {
    /// Validates and captures an exact delete or legacy-cleanup readback command.
    ///
    /// # Errors
    ///
    /// Returns access denied for any other action or target shape.
    pub fn new(command: CredentialBrokerCommand) -> Result<Self, SecureStoreError> {
        let reference = match (command.action(), command.target()) {
            (
                CredentialOperationAction::Revoke
                | CredentialOperationAction::RetiredVersionCleanup,
                CredentialBrokerTarget::Version(reference),
            ) => Some(reference.clone()),
            (
                CredentialOperationAction::LegacySourceCleanup,
                CredentialBrokerTarget::LegacySource,
            ) => None,
            _ => return Err(BrokerError::AccessDenied.into()),
        };
        Ok(Self { command, reference })
    }
}

pub(super) struct VersionStoreReadback<N> {
    native: N,
    access: ProviderCredentialAccessPolicy,
}

pub(super) trait LegacyCredentialSourceReadback: Send + Sync {
    fn legacy_source_status(
        &self,
        provider: &runne_provider::ProviderId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError>;
}

impl<T> LegacyCredentialSourceReadback for T
where
    T: ProviderCredentialStore,
{
    fn legacy_source_status(
        &self,
        provider: &runne_provider::ProviderId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        let provider = match provider.as_str() {
            "openai" => ProviderCredentialId::OpenAi,
            "deepseek" => ProviderCredentialId::DeepSeek,
            _ => return Err(BrokerError::Unsupported.into()),
        };
        self.provider_credential_status(provider, access)
    }
}

impl<N> VersionStoreReadback<N> {
    pub(super) const fn new(native: N, access: ProviderCredentialAccessPolicy) -> Self {
        Self { native, access }
    }
}

impl<N> ProviderCredentialReadback for VersionStoreReadback<N>
where
    N: NativeProviderCredentialVersionStore + LegacyCredentialSourceReadback,
{
    fn readback_exact_version(
        &self,
        input: ExactVersionReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        match self.native.version_status(&input.reference, &self.access)? {
            ProviderCredentialStatus::Configured => match input.command.action() {
                CredentialOperationAction::Pair => {
                    version_observation(&input.command, &input.reference, true)
                }
                CredentialOperationAction::MigrateLegacy => legacy_import_observation(
                    &input.command,
                    &input.reference,
                    self.native
                        .version_source_revision(&input.reference, &self.access)?,
                ),
                _ => Err(BrokerError::AccessDenied.into()),
            },
            ProviderCredentialStatus::Missing => Err(BrokerError::Missing.into()),
            ProviderCredentialStatus::Unsupported => Err(BrokerError::Unsupported.into()),
        }
    }

    fn readback_exact_absence(
        &self,
        input: ExactAbsenceReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        let status = match input.reference.as_ref() {
            Some(reference) => self.native.version_status(reference, &self.access)?,
            None => self
                .native
                .legacy_source_status(input.command.provider(), &self.access)?,
        };
        match status {
            ProviderCredentialStatus::Missing => match input.reference.as_ref() {
                Some(reference) => version_observation(&input.command, reference, false),
                None => legacy_observation(&input.command),
            },
            ProviderCredentialStatus::Configured => Err(BrokerError::Conflict.into()),
            ProviderCredentialStatus::Unsupported => Err(BrokerError::Unsupported.into()),
        }
    }
}

pub(super) struct VersionStoreDispatchMaterializer<N> {
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> VersionStoreDispatchMaterializer<N> {
    pub(super) const fn new(native: N, access: ProviderCredentialAccessPolicy) -> Self {
        Self { native, access }
    }
}

impl<N> ProviderCredentialDispatchMaterializer for VersionStoreDispatchMaterializer<N>
where
    N: NativeProviderCredentialVersionStore,
{
    fn materialize_active(
        &self,
        capability: &CredentialDispatchCapability,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.native.load_version(capability, &self.access)
    }
}

// Staged unwired: the canonical verification-effect boundary is composed in a
// later enrollment task; until then no production constructor exists.
#[allow(dead_code)]
pub(super) trait VerificationNativeMaterializer: Send + Sync {
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;
}

#[allow(dead_code)]
pub(super) struct VerificationMaterializerAdapter<N> {
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> VerificationMaterializerAdapter<N> {
    #[allow(dead_code)]
    pub(super) const fn new(native: N, access: ProviderCredentialAccessPolicy) -> Self {
        Self { native, access }
    }
}

impl<N> ProviderCredentialVerificationMaterializer for VerificationMaterializerAdapter<N>
where
    N: VerificationNativeMaterializer,
{
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.native
            .materialize_for_verification(capability, &self.access)
    }
}
