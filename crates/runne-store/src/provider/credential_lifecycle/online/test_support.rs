use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, BindCredentialReadback, ClaimCredentialOperation,
    CompleteCredentialOperation, CredentialBindingDigest, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialNativeEffectDisposition,
    CredentialOperationAction, CredentialOperationId, CredentialReadbackDisposition,
    CredentialReadinessDisposition, CredentialReadinessObservation, CredentialReadinessRevision,
    CredentialTicketAttempt, CredentialVersionRef, IssueCredentialTicketDigest,
    IssuedCredentialTicketAttempt, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
    ProviderId,
};

use super::SqliteProviderCredentialLifecycleStore;
use super::online_claim_test_support::{open_test_store, seal_claim};

pub(super) fn begin(operation: u8, key: &str, proof: u8) -> BeginCredentialOperation {
    begin_with_operation(operation, operation, key, proof, 200)
}

pub(super) fn begin_with_operation(
    command: u8,
    operation: u8,
    key: &str,
    proof: u8,
    expiry: u64,
) -> BeginCredentialOperation {
    let provider = provider();
    BeginCredentialOperation::new(
        CommandId::from_bytes([command.wrapping_add(20); 16]),
        IdempotencyKey::new(key).unwrap(),
        operation_id(operation),
        owner(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(proof),
        expiry,
    )
    .unwrap()
}

pub(super) fn store() -> SqliteProviderCredentialLifecycleStore {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.keep().join("online.sqlite");
    open_test_store(&path, 100)
}

pub(super) fn provider() -> ProviderId {
    ProviderId::new("openai").unwrap()
}

pub(super) fn operation(value: u8) -> CredentialOperationId {
    operation_id(value)
}

pub(super) fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

pub(super) fn ticket(
    operation: u8,
    attempt: u64,
    ticket: u8,
    continuation: u8,
) -> IssueCredentialTicketDigest {
    ticket_at(operation, attempt, ticket, continuation, 100, 200)
}

pub(super) fn ticket_at(
    operation: u8,
    _attempt: u64,
    ticket: u8,
    continuation: u8,
    issued_at: i64,
    expires_at: i64,
) -> IssueCredentialTicketDigest {
    IssueCredentialTicketDigest::new(
        operation_id(operation),
        digest(ticket),
        digest(continuation),
        expires_at - issued_at,
    )
    .unwrap()
}

pub(super) fn claim(
    store: &SqliteProviderCredentialLifecycleStore,
    operation: u8,
    attempt: u64,
    ticket: u8,
    continuation: u8,
    binding: u8,
) -> ClaimCredentialOperation {
    claim_at(store, operation, attempt, ticket, continuation, binding)
}

pub(super) fn claim_at(
    store: &SqliteProviderCredentialLifecycleStore,
    operation: u8,
    attempt: u64,
    ticket: u8,
    continuation: u8,
    binding: u8,
) -> ClaimCredentialOperation {
    ClaimCredentialOperation::new(
        receipt(store, operation, attempt),
        digest(ticket),
        digest(continuation),
        digest(binding),
        1,
        1,
    )
    .unwrap()
}

pub(super) fn revoke(
    operation: u8,
    key: &str,
    revision: u64,
    fence: u64,
) -> BeginCredentialOperation {
    BeginCredentialOperation::new(
        CommandId::from_bytes([operation.wrapping_add(20); 16]),
        IdempotencyKey::new(key).unwrap(),
        operation_id(operation),
        owner(),
        provider().clone(),
        CredentialOperationAction::Revoke,
        None,
        Some(CredentialVersionRef::new(provider(), 1).unwrap()),
        CredentialLifecycleRevision::new(revision).unwrap(),
        CredentialFence::new(fence).unwrap(),
        digest(operation.wrapping_add(1)),
        200,
    )
    .unwrap()
}

pub(super) fn admit_claim(store: &SqliteProviderCredentialLifecycleStore, id: u8, key: &str) {
    ProviderCredentialEnrollmentStore::begin(store, begin(id, key, id.wrapping_add(1))).unwrap();
    ProviderCredentialEnrollmentStore::issue_ticket_attempt(
        store,
        ticket(id, 1, id.wrapping_add(2), id.wrapping_add(3)),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::claim(
        store,
        seal_claim(
            store,
            claim(
                store,
                id,
                1,
                id.wrapping_add(2),
                id.wrapping_add(3),
                id.wrapping_add(4),
            ),
        ),
    )
    .unwrap();
}

pub(super) fn complete_pair(store: &SqliteProviderCredentialLifecycleStore, id: u8, key: &str) {
    admit_claim(store, id, key);
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store,
        ObserveNativeEffect::new(
            operation_id(id),
            CredentialNativeEffectDisposition::PossibleEffect,
        ),
    )
    .unwrap();
    let readback = BindCredentialReadback::new(
        operation_id(id),
        CredentialReadbackDisposition::ExactVersion,
        digest(id.wrapping_add(5)),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(store, readback).unwrap();
    ProviderCredentialEnrollmentStore::complete(store, pair_completion(id)).unwrap();
}

pub(super) fn pair_completion(id: u8) -> CompleteCredentialOperation {
    let active = CredentialVersionRef::new(provider(), 1).unwrap();
    let active_digest = CredentialBindingDigest::from_measured(*active.ref_digest()).unwrap();
    let readiness = CredentialReadinessObservation::new(
        operation_id(id.wrapping_add(100)),
        Some(operation_id(id)),
        provider(),
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(active_digest),
        digest(id.wrapping_add(6)),
        100,
    )
    .unwrap();
    CompleteCredentialOperation::new(
        operation_id(id),
        BindCredentialReadback::new(
            operation_id(id),
            CredentialReadbackDisposition::ExactVersion,
            digest(id.wrapping_add(5)),
        )
        .unwrap(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
    )
    .unwrap()
    .with_readiness_observation(readiness)
}

pub(super) fn ticket_state(
    store: &SqliteProviderCredentialLifecycleStore,
    operation: u8,
    attempt: u64,
) -> String {
    store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT state FROM provider_credential_ticket_attempts WHERE operation_id=?1 AND attempt=?2",
            rusqlite::params![operation_id(operation).as_bytes().as_slice(), attempt],
            |row| row.get(0),
        )
        .unwrap()
}

fn operation_id(value: u8) -> CredentialOperationId {
    CredentialOperationId::from_bytes([value; 16]).unwrap()
}

fn owner() -> CredentialInstallationOwnerId {
    CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap()
}

fn receipt(
    store: &SqliteProviderCredentialLifecycleStore,
    value: u8,
    attempt: u64,
) -> IssuedCredentialTicketAttempt {
    let snapshot =
        ProviderCredentialEnrollmentStore::load_operation(store, operation_id(value)).unwrap();
    let (issued_at, expires_at): (i64, i64) = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT issued_at, expires_at FROM provider_credential_ticket_attempts
             WHERE operation_id=?1 AND attempt=?2",
            rusqlite::params![operation_id(value).as_bytes().as_slice(), attempt],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    store
        .enrollment_authority
        .hydrate_issued_credential_ticket_attempt(
            snapshot,
            CredentialTicketAttempt::new(attempt).unwrap(),
            issued_at,
            expires_at,
        )
        .unwrap()
}
