use std::{cell::RefCell, collections::HashMap, path::Path, sync::Arc};

use runne_provider::{
    ClaimCredentialOperation, CredentialAuthorityPair, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentMeasurementAuthority, CredentialMeasurementSnapshot,
};

use super::SqliteProviderCredentialLifecycleStore;
use crate::schema::open_test_shared_writer;

thread_local! {
    static MEASUREMENT_AUTHORITIES: RefCell<HashMap<usize, CredentialEnrollmentMeasurementAuthority>> =
        RefCell::new(HashMap::new());
}

pub fn open_test_store(path: &Path, now: i64) -> SqliteProviderCredentialLifecycleStore {
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (store_authority, measurement_authority) = CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_authorities_and_now(
        path,
        lifecycle,
        store_authority,
        Arc::new(move || now),
    )
    .unwrap();
    let key = Arc::as_ptr(&store.connection) as usize;
    MEASUREMENT_AUTHORITIES.with(|authorities| {
        authorities.borrow_mut().insert(key, measurement_authority);
    });
    store
}

pub fn reopen_test_store(path: &Path, now: i64) -> SqliteProviderCredentialLifecycleStore {
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (store_authority, measurement_authority) = CredentialEnrollmentAuthorityPair::new().split();
    let connection = open_test_shared_writer(path).unwrap();
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_authorities_and_now(
        connection,
        lifecycle,
        store_authority,
        Arc::new(move || now),
    )
    .unwrap();
    let key = Arc::as_ptr(&store.connection) as usize;
    MEASUREMENT_AUTHORITIES.with(|authorities| {
        authorities.borrow_mut().insert(key, measurement_authority);
    });
    store
}

/// Opens a paired-authority store at a fixed verification clock and returns
/// BOTH halves of the enrollment pair: the store-side transition authority
/// the caller must keep for issuing legacy-import/recovery material the same
/// store will validate, and the measurement authority sealed to it. The
/// measurement half is NOT registered for [`measurements_for`]; callers hold
/// it directly.
pub fn open_test_store_with_authorities(
    path: &Path,
    now: i64,
) -> (
    SqliteProviderCredentialLifecycleStore,
    runne_provider::CredentialEnrollmentStoreAuthority,
    CredentialEnrollmentMeasurementAuthority,
) {
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (store_authority, measurement_authority) = CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_authorities_and_now(
        path,
        lifecycle,
        store_authority.clone(),
        Arc::new(move || now),
    )
    .unwrap();
    (store, store_authority, measurement_authority)
}

/// Reopens an existing paired-authority database at an advanced verification
/// clock so expiry boundaries can be exercised deterministically against the
/// SAME store-side seal that issued the original material.
pub fn reopen_test_store_with_authority(
    path: &Path,
    authority: runne_provider::CredentialEnrollmentStoreAuthority,
    now: i64,
) -> SqliteProviderCredentialLifecycleStore {
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let connection = open_test_shared_writer(path).unwrap();
    SqliteProviderCredentialLifecycleStore::open_with_connection_authorities_and_now(
        connection,
        lifecycle,
        authority,
        Arc::new(move || now),
    )
    .unwrap()
}

pub fn seal_claim(
    store: &SqliteProviderCredentialLifecycleStore,
    draft: ClaimCredentialOperation,
) -> ClaimCredentialOperation {
    seal_claim_with_context(store, draft, [201; 32], [207; 32])
}

pub(super) fn seal_claim_with_context(
    store: &SqliteProviderCredentialLifecycleStore,
    draft: ClaimCredentialOperation,
    release: [u8; 32],
    session: [u8; 32],
) -> ClaimCredentialOperation {
    let key = Arc::as_ptr(&store.connection) as usize;
    MEASUREMENT_AUTHORITIES.with(|authorities| {
        let authorities = authorities.borrow();
        let authority = authorities.get(&key).expect("registered test authority");
        let measurements = distinct_measurements(authority, &draft, release, session);
        let digest = authority
            .measure_claim_operation(&measurements, &draft)
            .unwrap();
        let bound = draft.bind_process_release_digest(digest).unwrap();
        authority.seal_claim_operation(measurements, bound).unwrap()
    })
}

pub fn measurements_for(
    store: &SqliteProviderCredentialLifecycleStore,
) -> CredentialEnrollmentMeasurementAuthority {
    let key = Arc::as_ptr(&store.connection) as usize;
    MEASUREMENT_AUTHORITIES.with(|authorities| {
        authorities
            .borrow()
            .get(&key)
            .expect("registered test authority")
            .clone()
    })
}

fn distinct_measurements(
    authority: &CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
    release: [u8; 32],
    session: [u8; 32],
) -> CredentialMeasurementSnapshot {
    CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([200; 32]).unwrap(),
        authority.release_manifest_digest(release).unwrap(),
        authority.desktop_executable_identity([202; 32]).unwrap(),
        authority.writer_executable_identity([203; 32]).unwrap(),
        authority.reader_executable_identity([204; 32]).unwrap(),
        authority.contract_bundle_digest([205; 32]).unwrap(),
        authority.daemon_authority_id([206; 32]).unwrap(),
        authority.protected_session_id(session).unwrap(),
        authority
            .desktop_supervisor_generation(claim.desktop_supervisor_generation())
            .unwrap(),
        authority.writer_launch_id([208; 32]).unwrap(),
        authority.writer_process_start_identity([209; 32]).unwrap(),
        authority.writer_process_handle_identity([210; 32]).unwrap(),
        authority.broker_channel_binding([211; 32]).unwrap(),
        authority
            .continuation_binding_digest(claim.continuation_binding_digest().as_bytes())
            .unwrap(),
    )
    .unwrap()
}
