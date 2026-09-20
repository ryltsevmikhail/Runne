use runne_provider::{CredentialAuthorityPair, CredentialNativeCreateValidator};
use runne_provider::{CredentialLifecycleError, ProviderCredentialVersionStore, ProviderId};
use rusqlite::{Connection, OptionalExtension};
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    time::Duration,
};

use super::support::*;

#[test]
fn native_created_stage_cannot_issue_a_new_native_create_claim() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("post-mark-claim.sqlite")
    };
    let (store, _native) = store_with_native(&path);
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0xE6; 16]).unwrap();
    let prepared = store
        .begin_provision(&provider, [0xE7; 16], &source)
        .unwrap();
    let native_created = store.mark_native_created(&prepared).unwrap();

    assert_eq!(
        store.claim_native_create(&native_created).unwrap_err(),
        CredentialLifecycleError::LifecycleClosed
    );
}

#[test]
fn post_mark_claim_is_rejected_after_delayed_use_through_deleted() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("delayed-post-mark-claim.sqlite")
    };
    let (store, native) = store_with_native(&path);
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0xE8; 16]).unwrap();
    let prepared = store
        .begin_provision(&provider, [0xE9; 16], &source)
        .unwrap();
    let native_created = store.mark_native_created(&prepared).unwrap();
    let delayed = store.claim_native_create(&native_created);

    store
        .activate(lease(
            native_created.version_ref().clone(),
            OWNER_A,
            i64::MAX,
            104,
        ))
        .unwrap();
    revoke(&store, native_created.version_ref().clone(), 104);
    let proof = native
        .delete(
            store
                .reconcile(100)
                .unwrap()
                .into_native_deletions()
                .pop()
                .unwrap(),
        )
        .unwrap();
    store.complete_native_delete(proof).unwrap();

    match delayed {
        Ok(claim) => assert_eq!(
            native.authorize_create(&claim).unwrap_err(),
            CredentialLifecycleError::StaleLease
        ),
        Err(error) => assert_eq!(error, CredentialLifecycleError::LifecycleClosed),
    }
}

#[test]
fn native_create_revalidates_durable_prepared_stage_at_point_of_use() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("durable-create-revalidation.sqlite")
    };
    let (store, native) = store_with_native(&path);
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0xEA; 16]).unwrap();
    let prepared = store
        .begin_provision(&provider, [0xEB; 16], &source)
        .unwrap();
    let claim = store.claim_native_create(&prepared).unwrap();

    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE provider_credential_provisions
             SET provision_state='NATIVE_CREATED' WHERE operation_id=?1",
            [prepared.operation_id().as_slice()],
        )
        .unwrap();

    assert_eq!(
        native.authorize_create(&claim).unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
}

#[test]
fn active_transition_invalidates_an_outstanding_native_create_claim() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("active-invalidates-create.sqlite")
    };
    let (store, native) = store_with_native(&path);
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0xEC; 16]).unwrap();
    let prepared = store
        .begin_provision(&provider, [0xED; 16], &source)
        .unwrap();
    let claim = store.claim_native_create(&prepared).unwrap();

    store
        .activate(lease(
            prepared.version_ref().clone(),
            OWNER_A,
            i64::MAX,
            105,
        ))
        .unwrap();

    assert_eq!(
        native.authorize_create(&claim).unwrap_err(),
        CredentialLifecycleError::StaleLease
    );
}

#[test]
fn claim_generation_stays_exclusive_until_stage_progression_commits() {
    let directory = tempfile::tempdir().unwrap();
    let path = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("generation-commit-boundary.sqlite")
    };
    let (lifecycle, native) = CredentialAuthorityPair::new().split();
    let store = Arc::new(
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_at_with_authority(
            &path,
            lifecycle.clone(),
            100,
        )
        .unwrap(),
    );
    let provider = ProviderId::new("openai").unwrap();
    let source = store.provision_source([0xEE; 16]).unwrap();
    let prepared = store
        .begin_provision(&provider, [0xEF; 16], &source)
        .unwrap();
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    std::thread::scope(|scope| {
        let pending_store = Arc::clone(&store);
        let pending_provision = prepared.clone();
        let mark = scope.spawn(move || pending_store.mark_native_created(&pending_provision));
        let mut progression_is_exclusive = false;
        for _ in 0..100 {
            if lifecycle.native_create_progression_is_exclusive().unwrap() {
                progression_is_exclusive = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(progression_is_exclusive);

        let (sender, receiver) = mpsc::sync_channel(1);
        let issuer = lifecycle.clone();
        let verifier = native.clone();
        let reference = prepared.version_ref().clone();
        let operation_id = *prepared.operation_id();
        let validator_path = path.clone();
        scope.spawn(move || {
            let source = issuer.issue_provision_source([0xEE; 16]).unwrap();
            let claim = issuer
                .native_create_issuer()
                .unwrap()
                .issue_native_create(
                    reference,
                    &source,
                    Arc::new(DurablePreparedValidator {
                        path: validator_path,
                        operation_id,
                    }),
                )
                .unwrap();
            sender
                .send(verifier.authorize_create(&claim).map(|_| ()))
                .unwrap();
        });

        let early = receiver.recv_timeout(Duration::from_millis(100));
        let issuance_was_blocked = early.is_err();
        blocker.execute_batch("COMMIT").unwrap();
        mark.join().unwrap().unwrap();
        let result =
            early.unwrap_or_else(|_| receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        assert!(issuance_was_blocked);
        assert_eq!(result.unwrap_err(), CredentialLifecycleError::StaleLease);
    });
}

struct DurablePreparedValidator {
    path: PathBuf,
    operation_id: [u8; 16],
}

impl CredentialNativeCreateValidator for DurablePreparedValidator {
    fn validate(&self) -> Result<(), CredentialLifecycleError> {
        let state = Connection::open(&self.path)
            .map_err(|_| CredentialLifecycleError::StoreUnavailable)?
            .query_row(
                "SELECT provision_state FROM provider_credential_provisions
                 WHERE operation_id=?1",
                [self.operation_id.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| CredentialLifecycleError::StoreUnavailable)?;
        if state.as_deref() == Some("PREPARED") {
            Ok(())
        } else {
            Err(CredentialLifecycleError::StaleLease)
        }
    }
}
