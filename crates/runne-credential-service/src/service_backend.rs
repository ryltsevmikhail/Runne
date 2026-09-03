use runne_credential_service_core::{
    CredentialBackendResult, CredentialMutationEffect, CredentialRuntimeReadEffect,
    CredentialRuntimeReadObservation,
};
use runne_macos_xpc::CredentialServiceXpcError;

use crate::keychain::KeychainBackend;

pub enum ServiceBackend {
    Keychain,
    #[cfg(feature = "test-support")]
    Memory(MemoryBackend),
}

impl ServiceBackend {
    pub fn new(local_fixture: bool) -> Result<Self, CredentialServiceXpcError> {
        #[cfg(feature = "test-support")]
        if local_fixture {
            return Ok(Self::Memory(MemoryBackend::default()));
        }
        if local_fixture {
            return Err(CredentialServiceXpcError::Rejected);
        }
        Ok(Self::Keychain)
    }

    pub fn mutate(&mut self, effect: CredentialMutationEffect<'_>) -> CredentialBackendResult<()> {
        match self {
            Self::Keychain => KeychainBackend::mutate(effect),
            #[cfg(feature = "test-support")]
            Self::Memory(backend) => backend.mutate(effect),
        }
    }

    pub fn read(
        &self,
        effect: &CredentialRuntimeReadEffect<'_>,
    ) -> CredentialRuntimeReadObservation {
        match self {
            Self::Keychain => KeychainBackend::read(effect),
            #[cfg(feature = "test-support")]
            Self::Memory(backend) => backend.read(effect),
        }
    }
}

#[cfg(feature = "test-support")]
#[derive(Default)]
pub struct MemoryBackend {
    items: Vec<MemoryItem>,
}

#[cfg(feature = "test-support")]
struct MemoryItem {
    reference: runne_provider::CredentialVersionRef,
    material: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg(feature = "test-support")]
impl MemoryBackend {
    fn mutate(&mut self, effect: CredentialMutationEffect<'_>) -> CredentialBackendResult<()> {
        use runne_provider::CredentialOperationAction;

        let command = effect.command();
        let Some(reference) = command.target().version_ref().cloned() else {
            return CredentialBackendResult::Unsupported;
        };
        if command.provider() != reference.provider() {
            return CredentialBackendResult::AccessDenied;
        }
        match command.action() {
            CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
                if self.items.iter().any(|item| item.reference == reference) {
                    return CredentialBackendResult::AccessDenied;
                }
                let Some(material) = effect.into_material() else {
                    return CredentialBackendResult::AccessDenied;
                };
                let mut retained = zeroize::Zeroizing::new(Vec::new());
                material.consume(|bytes| retained.extend_from_slice(bytes));
                self.items.push(MemoryItem {
                    reference,
                    material: retained,
                });
                CredentialBackendResult::Observed(())
            }
            CredentialOperationAction::Revoke
            | CredentialOperationAction::RetiredVersionCleanup => {
                if effect.into_material().is_some() {
                    return CredentialBackendResult::AccessDenied;
                }
                let Some(index) = self
                    .items
                    .iter()
                    .position(|item| item.reference == reference)
                else {
                    return CredentialBackendResult::Absent;
                };
                self.items.remove(index);
                CredentialBackendResult::Observed(())
            }
            CredentialOperationAction::LegacySourceCleanup
            | CredentialOperationAction::WriterIdentityMigrationEffect
            | CredentialOperationAction::WriterIdentityMigrationVerify => {
                CredentialBackendResult::Unsupported
            }
        }
    }

    fn read(&self, effect: &CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation {
        let reference = match effect {
            CredentialRuntimeReadEffect::Metadata(reference)
            | CredentialRuntimeReadEffect::PointOfUse(reference) => *reference,
        };
        let item = self.items.iter().find(|item| &item.reference == reference);
        match effect {
            CredentialRuntimeReadEffect::Metadata(_) => CredentialRuntimeReadObservation::Metadata(
                item.map_or(CredentialBackendResult::Absent, |_| {
                    CredentialBackendResult::Observed(())
                }),
            ),
            CredentialRuntimeReadEffect::PointOfUse(_) => {
                CredentialRuntimeReadObservation::PointOfUse(item.map_or(
                    CredentialBackendResult::Absent,
                    |item| {
                        runne_provider::CredentialMaterial::from_bytes(item.material.to_vec())
                            .map_or(
                                CredentialBackendResult::Unavailable,
                                CredentialBackendResult::Observed,
                            )
                    },
                ))
            }
        }
    }
}
