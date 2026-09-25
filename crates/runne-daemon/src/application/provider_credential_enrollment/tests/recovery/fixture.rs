use std::sync::Mutex;

use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BindCredentialReadback, CredentialBindingDigest, CredentialCompletionReceipt,
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleError, CredentialLifecycleRevision, CredentialLifecycleSnapshot,
    CredentialNativeEffectDisposition, CredentialOperationAction, CredentialOperationId,
    CredentialOperationSnapshot, CredentialOperationState, CredentialReadinessRevision,
    CredentialRecoveryWork, CredentialTerminalDisposition, CredentialTicketAttempt,
    CredentialVersionRef, ProviderId,
};

mod legacy;
mod reader;
mod receipt;
mod store;

pub(in super::super) use reader::StatefulReader;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum FailurePoint {
    None,
    Mark,
    Readback,
    Bind,
    Complete,
}

pub(in super::super) struct Fixture {
    authority: runne_provider::CredentialEnrollmentStoreAuthority,
    operation: Mutex<CredentialOperationSnapshot>,
    command: runne_provider::CredentialBrokerCommand,
    lifecycle: CredentialLifecycleSnapshot,
    successor: CredentialLifecycleSnapshot,
    failure: FailurePoint,
    events: Mutex<Vec<&'static str>>,
    receipt: Mutex<Option<CredentialCompletionReceipt>>,
}

impl Fixture {
    pub(in super::super) fn retired_cleanup(failure: FailurePoint) -> Self {
        Self::new(CredentialOperationAction::RetiredVersionCleanup, failure)
    }

    pub(in super::super) fn retired_cleanup_after_revoke() -> Self {
        let mut fixture = Self::retired_cleanup(FailurePoint::None);
        fixture.lifecycle = CredentialLifecycleSnapshot::new(
            provider(),
            None,
            revision(2),
            fence(2),
            readiness(2),
            3,
        )
        .unwrap();
        fixture
    }

    pub(super) fn legacy_cleanup(failure: FailurePoint) -> Self {
        Self::new(CredentialOperationAction::LegacySourceCleanup, failure)
    }

    pub(super) fn writer_identity_migration(action: CredentialOperationAction) -> Self {
        Self::new(action, FailurePoint::None)
    }

    pub(super) fn new(action: CredentialOperationAction, failure: FailurePoint) -> Self {
        let base = if action == CredentialOperationAction::LegacySourceCleanup {
            2
        } else {
            1
        };
        let (authority, _) = CredentialEnrollmentAuthorityPair::new().split();
        let provider = provider();
        let operation_id = operation();
        let attempt = CredentialTicketAttempt::new(1).unwrap();
        let target = match action {
            CredentialOperationAction::Revoke
            | CredentialOperationAction::RetiredVersionCleanup => {
                Some(CredentialVersionRef::new(provider.clone(), 1).unwrap())
            }
            _ => None,
        };
        let mut metadata = authority
            .hydrate_persisted_credential_operation_metadata(
                CommandId::from_bytes([1; 16]),
                IdempotencyKey::new("recovery").unwrap(),
                owner(),
                revision(base),
                fence(base),
                digest(3),
                1,
                1,
                Some(digest(9)),
                Some(attempt),
            )
            .unwrap()
            .with_claim(digest(4), digest(5));
        let command_target = match action {
            CredentialOperationAction::Revoke
            | CredentialOperationAction::RetiredVersionCleanup => {
                runne_provider::CredentialBrokerTarget::Version(target.clone().unwrap())
            }
            CredentialOperationAction::LegacySourceCleanup => {
                let binding = legacy::binding();
                metadata = metadata.with_legacy_cleanup_binding(binding.clone());
                runne_provider::CredentialBrokerTarget::ExactLegacySource(binding)
            }
            CredentialOperationAction::WriterIdentityMigrationEffect
            | CredentialOperationAction::WriterIdentityMigrationVerify => {
                let phase = if action == CredentialOperationAction::WriterIdentityMigrationEffect {
                    runne_provider::WriterIdentityMigrationPhase::OldWriterEffect
                } else {
                    runne_provider::WriterIdentityMigrationPhase::NewWriterVerify
                };
                metadata = metadata.with_migration(
                    authority.hydrate_persisted_credential_migration_metadata(
                        CredentialOperationId::from_bytes([6; 16]).unwrap(),
                        phase,
                        digest(10),
                        digest(11),
                        digest(12),
                    ),
                );
                runne_provider::CredentialBrokerTarget::Migration {
                    migration_id: CredentialOperationId::from_bytes([6; 16]).unwrap(),
                    phase,
                }
            }
            _ => unreachable!(),
        };
        let operation = CredentialOperationSnapshot::new(
            operation_id,
            provider.clone(),
            action,
            CredentialOperationState::Claimed,
            None,
            target,
            metadata,
        )
        .unwrap();
        let binding = operation
            .metadata()
            .migration()
            .map(|value| value.binding_digest());
        let command = runne_provider::CredentialBrokerCommand::new(
            operation_id,
            attempt,
            provider.clone(),
            action,
            command_target,
            revision(base),
            fence(base),
            binding,
        )
        .unwrap();
        let fenced_revoke = action == CredentialOperationAction::Revoke;
        let lifecycle = CredentialLifecycleSnapshot::new(
            provider.clone(),
            (!fenced_revoke).then(|| CredentialVersionRef::new(provider.clone(), 2).unwrap()),
            revision(base + u64::from(fenced_revoke)),
            fence(base + u64::from(fenced_revoke)),
            readiness(base + u64::from(fenced_revoke)),
            3,
        )
        .unwrap();
        let successor = if action == CredentialOperationAction::LegacySourceCleanup || fenced_revoke
        {
            lifecycle.clone()
        } else {
            CredentialLifecycleSnapshot::new(
                provider,
                lifecycle.active_version().cloned(),
                revision(2),
                fence(2),
                readiness(2),
                3,
            )
            .unwrap()
        };
        Self {
            authority,
            operation: Mutex::new(operation),
            command,
            lifecycle,
            successor,
            failure,
            events: Mutex::new(Vec::new()),
            receipt: Mutex::new(None),
        }
    }

    pub(super) fn state(&self) -> CredentialOperationState {
        self.operation.lock().unwrap().state()
    }

    pub(in super::super) fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }

    pub(super) fn receipt(&self) -> Option<CredentialCompletionReceipt> {
        self.receipt.lock().unwrap().take()
    }

    pub(super) fn event(&self, value: &'static str) {
        self.events.lock().unwrap().push(value);
    }

    pub(super) const fn failure(&self) -> FailurePoint {
        self.failure
    }

    pub(super) fn work(&self) -> CredentialRecoveryWork {
        CredentialRecoveryWork::new(self.operation.lock().unwrap().clone())
            .unwrap()
            .with_command(self.command.clone())
            .unwrap()
    }

    pub(super) fn transition(
        &self,
        state: CredentialOperationState,
        readback: Option<BindCredentialReadback>,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        let current = self.operation.lock().unwrap().clone();
        let mut metadata = current.metadata().clone();
        if matches!(
            state,
            CredentialOperationState::NativeEffectObserved
                | CredentialOperationState::ReadbackVerified
                | CredentialOperationState::Completed
        ) {
            metadata =
                metadata.with_native_effect(CredentialNativeEffectDisposition::PossibleEffect);
        }
        if let Some(readback) = readback {
            metadata =
                metadata.with_readback(readback.disposition(), readback.observation_digest());
        }
        if state == CredentialOperationState::Completed {
            metadata = metadata.with_terminal(CredentialTerminalDisposition::Completed);
        } else if state == CredentialOperationState::Failed {
            metadata =
                metadata.with_terminal(CredentialTerminalDisposition::FailedWithVerifiedAbsence);
        }
        let next = CredentialOperationSnapshot::new(
            current.operation_id(),
            current.provider().clone(),
            current.action(),
            state,
            current.allocated_credential_version().cloned(),
            current.target_credential_version().cloned(),
            metadata,
        )
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
        *self.operation.lock().unwrap() = next.clone();
        Ok(next)
    }

    pub(super) fn lifecycle(&self) -> CredentialLifecycleSnapshot {
        self.lifecycle.clone()
    }
}

pub(super) fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn operation() -> CredentialOperationId {
    CredentialOperationId::from_bytes([7; 16]).unwrap()
}
fn provider() -> ProviderId {
    ProviderId::new("openai").unwrap()
}
fn owner() -> CredentialInstallationOwnerId {
    CredentialInstallationOwnerId::from_bytes([2; 32]).unwrap()
}
fn revision(value: u64) -> CredentialLifecycleRevision {
    CredentialLifecycleRevision::new(value).unwrap()
}
fn fence(value: u64) -> CredentialFence {
    CredentialFence::new(value).unwrap()
}
fn readiness(value: u64) -> CredentialReadinessRevision {
    CredentialReadinessRevision::new(value).unwrap()
}
