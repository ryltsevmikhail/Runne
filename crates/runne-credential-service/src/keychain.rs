mod item;

use runne_credential_service_core::{
    CredentialBackendResult, CredentialMutationEffect, CredentialRuntimeReadEffect,
    CredentialRuntimeReadObservation,
};
use runne_provider::{CredentialMaterial, CredentialOperationAction, CredentialVersionRef};

use item::CredentialItemLocator;

const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25_299;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
const ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25_307;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialKeychainStatus {
    Observed,
    Absent,
    Duplicate,
    AccessDenied,
    Unavailable,
    Uncertain,
}

const fn map_keychain_read_status(status: i32) -> CredentialKeychainStatus {
    match status {
        ERR_SEC_SUCCESS => CredentialKeychainStatus::Observed,
        ERR_SEC_ITEM_NOT_FOUND => CredentialKeychainStatus::Absent,
        ERR_SEC_NOT_AVAILABLE | ERR_SEC_NO_DEFAULT_KEYCHAIN | ERR_SEC_INTERACTION_NOT_ALLOWED => {
            CredentialKeychainStatus::Unavailable
        }
        ERR_SEC_MISSING_ENTITLEMENT => CredentialKeychainStatus::AccessDenied,
        _ => CredentialKeychainStatus::Uncertain,
    }
}

const fn map_keychain_read_result(status: i32, has_value: bool) -> CredentialKeychainStatus {
    match (map_keychain_read_status(status), has_value) {
        (CredentialKeychainStatus::Observed, false) => CredentialKeychainStatus::Unavailable,
        (mapped, _) => mapped,
    }
}

const fn map_keychain_write_status(status: i32) -> CredentialKeychainStatus {
    match status {
        ERR_SEC_SUCCESS => CredentialKeychainStatus::Observed,
        ERR_SEC_DUPLICATE_ITEM => CredentialKeychainStatus::Duplicate,
        ERR_SEC_ITEM_NOT_FOUND => CredentialKeychainStatus::Absent,
        ERR_SEC_NOT_AVAILABLE | ERR_SEC_NO_DEFAULT_KEYCHAIN | ERR_SEC_INTERACTION_NOT_ALLOWED => {
            CredentialKeychainStatus::Unavailable
        }
        ERR_SEC_MISSING_ENTITLEMENT => CredentialKeychainStatus::AccessDenied,
        _ => CredentialKeychainStatus::Uncertain,
    }
}

impl CredentialKeychainStatus {
    const fn into_backend_unit(self) -> CredentialBackendResult<()> {
        match self {
            Self::Observed => CredentialBackendResult::Observed(()),
            Self::Absent => CredentialBackendResult::Absent,
            Self::Duplicate | Self::AccessDenied => CredentialBackendResult::AccessDenied,
            Self::Unavailable => CredentialBackendResult::Unavailable,
            Self::Uncertain => CredentialBackendResult::Uncertain,
        }
    }
}

#[derive(Default)]
pub struct KeychainBackend;

struct CredentialStoredRecord {
    material: CredentialMaterial,
    source_revision: Option<[u8; 16]>,
}

impl KeychainBackend {
    fn store(
        reference: &CredentialVersionRef,
        material: CredentialMaterial,
        source_revision: Option<[u8; 16]>,
    ) -> CredentialBackendResult<()> {
        let locator = CredentialItemLocator::new(reference);
        let mut result = CredentialBackendResult::Uncertain;
        material.consume(|bytes| {
            result = native::add(&locator, bytes, source_revision).into_backend_unit();
        });
        result
    }

    fn delete(reference: &CredentialVersionRef) -> CredentialBackendResult<()> {
        native::delete(&CredentialItemLocator::new(reference)).into_backend_unit()
    }

    pub fn mutate(effect: CredentialMutationEffect<'_>) -> CredentialBackendResult<()> {
        let command = effect.command();
        let Some(reference) = command.target().version_ref().cloned() else {
            return CredentialBackendResult::Unsupported;
        };
        if command.provider() != reference.provider() {
            return CredentialBackendResult::AccessDenied;
        }
        let action = command.action();
        let source_revision = effect.source_revision();
        match action {
            CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => effect
                .into_material()
                .map_or(CredentialBackendResult::AccessDenied, |material| {
                    Self::store(&reference, material, source_revision)
                }),
            CredentialOperationAction::Revoke
            | CredentialOperationAction::RetiredVersionCleanup => {
                if effect.into_material().is_some() {
                    CredentialBackendResult::AccessDenied
                } else {
                    Self::delete(&reference)
                }
            }
            CredentialOperationAction::LegacySourceCleanup
            | CredentialOperationAction::WriterIdentityMigrationEffect
            | CredentialOperationAction::WriterIdentityMigrationVerify => {
                CredentialBackendResult::Unsupported
            }
        }
    }

    pub fn read(effect: &CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation {
        match effect {
            CredentialRuntimeReadEffect::Metadata(reference) => {
                let result = match native::read_record(&CredentialItemLocator::new(reference)) {
                    Ok(record) => {
                        if let Some(revision) = record.source_revision {
                            return CredentialRuntimeReadObservation::LegacyMetadata(
                                CredentialBackendResult::Observed(revision),
                            );
                        }
                        CredentialBackendResult::Observed(())
                    }
                    Err(status) => status.into_backend_unit(),
                };
                CredentialRuntimeReadObservation::Metadata(result)
            }
            CredentialRuntimeReadEffect::PointOfUse(reference) => {
                let result = match native::read_record(&CredentialItemLocator::new(reference)) {
                    Ok(record) => CredentialBackendResult::Observed(record.material),
                    Err(status) => match status.into_backend_unit() {
                        CredentialBackendResult::Absent => CredentialBackendResult::Absent,
                        CredentialBackendResult::AccessDenied => {
                            CredentialBackendResult::AccessDenied
                        }
                        CredentialBackendResult::Unsupported => {
                            CredentialBackendResult::Unsupported
                        }
                        CredentialBackendResult::Observed(())
                        | CredentialBackendResult::Unavailable => {
                            CredentialBackendResult::Unavailable
                        }
                        CredentialBackendResult::Uncertain => CredentialBackendResult::Uncertain,
                    },
                };
                CredentialRuntimeReadObservation::PointOfUse(result)
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod native {
    use super::{CredentialItemLocator, CredentialKeychainStatus};

    pub(super) fn add(
        _: &CredentialItemLocator,
        _: &[u8],
        _: Option<[u8; 16]>,
    ) -> CredentialKeychainStatus {
        CredentialKeychainStatus::Unavailable
    }
    pub(super) fn read_record(
        _: &CredentialItemLocator,
    ) -> Result<super::CredentialStoredRecord, CredentialKeychainStatus> {
        Err(CredentialKeychainStatus::Unavailable)
    }
    pub(super) fn delete(_: &CredentialItemLocator) -> CredentialKeychainStatus {
        CredentialKeychainStatus::Unavailable
    }
}

#[cfg(target_os = "macos")]
mod native;

#[cfg(test)]
mod tests;
