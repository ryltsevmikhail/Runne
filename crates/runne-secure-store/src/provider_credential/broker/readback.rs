use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget,
    CredentialOperationAction, CredentialVersionRef,
};

use super::errors::BrokerError;
use super::readback_observation::{
    legacy_import_observation, legacy_observation, version_observation,
};
use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialStatus, SecureStoreError,
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

    /// Returns the exact command used to bind a service metadata read.
    #[must_use]
    pub const fn command(&self) -> &CredentialBrokerCommand {
        &self.command
    }

    /// Returns the immutable version queried through the service.
    #[must_use]
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        &self.reference
    }

    /// Converts service metadata into the canonical readback observation.
    ///
    /// # Errors
    ///
    /// Preserves missing-version and legacy-source-revision failures.
    pub fn observe_service_presence(
        self,
        present: bool,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        self.observe_service_metadata(present, None)
    }

    /// Binds imported-version readback to its atomically persisted source revision.
    ///
    /// # Errors
    /// Rejects missing revision for imports and revision metadata on ordinary or absent records.
    pub fn observe_service_metadata(
        self,
        present: bool,
        source_revision: Option<crate::ProviderCredentialSourceRevision>,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        if let Some(revision) = source_revision {
            return if present && self.command.action() == CredentialOperationAction::MigrateLegacy {
                legacy_import_observation(&self.command, &self.reference, revision)
            } else {
                Err(BrokerError::AccessDenied.into())
            };
        }
        match self.command.action() {
            CredentialOperationAction::Pair => {
                version_observation(&self.command, &self.reference, present)
            }
            CredentialOperationAction::MigrateLegacy if !present => {
                version_observation(&self.command, &self.reference, false)
            }
            CredentialOperationAction::MigrateLegacy => {
                Err(SecureStoreError::ProviderCredentialSourceRevisionUnavailable)
            }
            _ => Err(BrokerError::AccessDenied.into()),
        }
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
                CredentialBrokerTarget::ExactLegacySource(_),
            ) => None,
            _ => return Err(BrokerError::AccessDenied.into()),
        };
        Ok(Self { command, reference })
    }

    /// Returns the exact command used to bind a service metadata read.
    #[must_use]
    pub const fn command(&self) -> &CredentialBrokerCommand {
        &self.command
    }

    /// Returns the immutable version, or `None` for the legacy source.
    #[must_use]
    pub const fn version_ref(&self) -> Option<&CredentialVersionRef> {
        self.reference.as_ref()
    }

    /// Converts service metadata into the canonical absence observation.
    ///
    /// # Errors
    ///
    /// Rejects a still-present target as a conflicting mutation outcome.
    pub fn observe_service_presence(
        self,
        present: bool,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        if present {
            return Err(BrokerError::Conflict.into());
        }
        match self.reference.as_ref() {
            Some(reference) => version_observation(&self.command, reference, false),
            None => legacy_observation(&self.command),
        }
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

impl LegacyCredentialSourceReadback for crate::NativeProviderCredentialStore {
    fn legacy_source_status(
        &self,
        provider: &runne_provider::ProviderId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        let provider = match provider.as_str() {
            "openai" => ProviderCredentialId::OpenAi,
            "deepseek" => ProviderCredentialId::DeepSeek,
            "local-engine" => ProviderCredentialId::LocalEngine,
            _ => return Err(BrokerError::Unsupported.into()),
        };
        #[cfg(target_os = "macos")]
        {
            self.legacy_source_metadata_presence(provider, access)
                .map(|present| {
                    if present {
                        ProviderCredentialStatus::Configured
                    } else {
                        ProviderCredentialStatus::Missing
                    }
                })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (provider, access);
            Err(BrokerError::Unsupported.into())
        }
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
            ProviderCredentialStatus::Configured => {
                #[cfg(feature = "test-support")]
                if runne_api::test_support::local_native_enrollment_enabled() {
                    crate::test_support::prove_current_reader_can_load_exact(
                        &input.reference,
                        &self.access,
                    )?;
                }
                match input.command.action() {
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
                }
            }
            ProviderCredentialStatus::Missing => {
                version_observation(&input.command, &input.reference, false)
            }
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
