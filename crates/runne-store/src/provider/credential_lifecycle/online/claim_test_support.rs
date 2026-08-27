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

pub(crate) fn open_test_store(path: &Path, now: i64) -> SqliteProviderCredentialLifecycleStore {
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

pub(crate) fn reopen_test_store(path: &Path, now: i64) -> SqliteProviderCredentialLifecycleStore {
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

pub(super) fn seal_claim(
    store: &SqliteProviderCredentialLifecycleStore,
    draft: ClaimCredentialOperation,
) -> ClaimCredentialOperation {
    let key = Arc::as_ptr(&store.connection) as usize;
    MEASUREMENT_AUTHORITIES.with(|authorities| {
        let authorities = authorities.borrow();
        let authority = authorities.get(&key).expect("registered test authority");
        let measurements = distinct_measurements(authority, &draft);
        let digest = authority
            .measure_claim_operation(&measurements, &draft)
            .unwrap();
        let bound = draft.bind_process_release_digest(digest).unwrap();
        authority.seal_claim_operation(measurements, bound).unwrap()
    })
}

fn distinct_measurements(
    authority: &CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
) -> CredentialMeasurementSnapshot {
    CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([200; 32]).unwrap(),
        authority.release_manifest_digest([201; 32]).unwrap(),
        authority.desktop_executable_identity([202; 32]).unwrap(),
        authority.writer_executable_identity([203; 32]).unwrap(),
        authority.reader_executable_identity([204; 32]).unwrap(),
        authority.contract_bundle_digest([205; 32]).unwrap(),
        authority.daemon_authority_id([206; 32]).unwrap(),
        authority.protected_session_id([207; 32]).unwrap(),
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
