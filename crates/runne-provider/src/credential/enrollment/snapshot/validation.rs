use crate::CredentialVersionRef;

use super::super::{
    CredentialOperationAction, CredentialOperationMetadata, CredentialOperationState,
    CredentialTerminalDisposition, WriterIdentityMigrationPhase,
};

pub(super) fn valid_snapshot_shape(
    action: CredentialOperationAction,
    state: CredentialOperationState,
    allocation: Option<&CredentialVersionRef>,
    target: Option<&CredentialVersionRef>,
    metadata: &CredentialOperationMetadata,
) -> bool {
    versions_match(action, allocation, target)
        && migration_matches(action, metadata)
        && state_matches(state, metadata)
}

fn versions_match(
    action: CredentialOperationAction,
    allocation: Option<&CredentialVersionRef>,
    target: Option<&CredentialVersionRef>,
) -> bool {
    matches!(
        (action, allocation.is_some(), target.is_some()),
        (
            CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy,
            true,
            false
        ) | (
            CredentialOperationAction::Revoke | CredentialOperationAction::RetiredVersionCleanup,
            false,
            true
        ) | (
            CredentialOperationAction::LegacySourceCleanup
                | CredentialOperationAction::WriterIdentityMigrationEffect
                | CredentialOperationAction::WriterIdentityMigrationVerify,
            false,
            false
        )
    )
}

fn migration_matches(
    action: CredentialOperationAction,
    metadata: &CredentialOperationMetadata,
) -> bool {
    match action {
        CredentialOperationAction::WriterIdentityMigrationEffect => metadata
            .migration()
            .is_some_and(|value| value.phase() == WriterIdentityMigrationPhase::OldWriterEffect),
        CredentialOperationAction::WriterIdentityMigrationVerify => metadata
            .migration()
            .is_some_and(|value| value.phase() == WriterIdentityMigrationPhase::NewWriterVerify),
        _ => metadata.migration().is_none(),
    }
}

fn state_matches(state: CredentialOperationState, metadata: &CredentialOperationMetadata) -> bool {
    let continuation = metadata.continuation_binding_digest().is_some();
    let binding = metadata.process_release_binding_digest().is_some();
    let readback_disposition = metadata.readback_disposition().is_some();
    let readback_digest = metadata.readback_observation_digest().is_some();
    if !pair(continuation, binding) || !pair(readback_disposition, readback_digest) {
        return false;
    }
    let claim = continuation;
    let readback = readback_disposition;
    let native = metadata.native_effect_disposition().is_some();
    let terminal = metadata.terminal_disposition();
    let tombstone = metadata.tombstone_digest().is_some();
    match state {
        CredentialOperationState::Prepared => {
            !claim && !native && !readback && terminal.is_none() && !tombstone
        }
        CredentialOperationState::Claimed => {
            claim && !native && !readback && terminal.is_none() && !tombstone
        }
        CredentialOperationState::NativeEffectObserved => {
            claim && native && !readback && terminal.is_none() && !tombstone
        }
        CredentialOperationState::ReadbackVerified => {
            claim && native && readback && terminal.is_none() && !tombstone
        }
        CredentialOperationState::Completed => {
            terminal == Some(CredentialTerminalDisposition::Completed)
                && predecessor_shape(claim, native, readback)
                && !tombstone
        }
        CredentialOperationState::Failed => {
            terminal == Some(CredentialTerminalDisposition::FailedWithVerifiedAbsence)
                && failed_predecessor_shape(claim, native, readback)
                && !tombstone
        }
        CredentialOperationState::Expired => {
            terminal == Some(CredentialTerminalDisposition::Expired)
                && !claim
                && !native
                && !readback
                && !tombstone
        }
        CredentialOperationState::Cancelled => {
            terminal == Some(CredentialTerminalDisposition::Cancelled)
                && !claim
                && !native
                && !readback
                && !tombstone
        }
        CredentialOperationState::Tombstoned => {
            tombstone
                && terminal.is_some()
                && tombstone_predecessor_shape(terminal, claim, native, readback)
        }
    }
}

fn pair(left: bool, right: bool) -> bool {
    left == right
}

fn predecessor_shape(claim: bool, native: bool, readback: bool) -> bool {
    claim && native && readback
}

fn failed_predecessor_shape(claim: bool, native: bool, readback: bool) -> bool {
    (!claim && !native && !readback)
        || (claim && !native && readback)
        || (claim && native && readback)
}

fn tombstone_predecessor_shape(
    terminal: Option<CredentialTerminalDisposition>,
    claim: bool,
    native: bool,
    readback: bool,
) -> bool {
    match terminal {
        Some(CredentialTerminalDisposition::Completed) => {
            predecessor_shape(claim, native, readback)
        }
        Some(CredentialTerminalDisposition::FailedWithVerifiedAbsence) => {
            failed_predecessor_shape(claim, native, readback)
        }
        Some(CredentialTerminalDisposition::Expired | CredentialTerminalDisposition::Cancelled) => {
            !claim && !native && !readback
        }
        Some(CredentialTerminalDisposition::Tombstoned) | None => false,
    }
}
