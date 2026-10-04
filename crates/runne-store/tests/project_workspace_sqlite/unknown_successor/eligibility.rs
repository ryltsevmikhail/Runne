use super::fixture::running;
use super::tests::{Resolver, context};
use runne_application::commands::CompleteTaskRunInput;
use runne_application::ports::EventStore;
use runne_application::service::TaskRunService;
use std::sync::Arc;

#[test]
fn terminal_taskrun_with_unknown_remote_effect_is_not_successor_eligible() {
    let fixture = running("unknown-successor-terminal-effect", 0x49);
    TaskRunService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        super::fixture::runtime_authority(),
    )
    .complete_task_run(
        &context(0x4e, "terminalize-unknown-effect"),
        CompleteTaskRunInput {
            taskrun_id: fixture.taskrun_id,
            expected_version: fixture.version,
            result: runne_domain::command::TerminalResult::Success,
        },
    )
    .unwrap();
    let stream = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    assert_eq!(stream.current_version, fixture.version + 1);
    let repository = fixture
        .database
        .store
        .unknown_successor_repository(Arc::new(Resolver));
    assert!(
        !repository
            .is_eligible(fixture.taskrun_id, stream.current_version)
            .unwrap()
    );
}

#[test]
fn ambiguous_remote_intents_are_not_successor_eligible() {
    let fixture = running("unknown-successor-ambiguous-intent", 0x59);
    let repository = fixture
        .database
        .store
        .unknown_successor_repository(Arc::new(Resolver));
    assert!(
        repository
            .is_eligible(fixture.taskrun_id, fixture.version)
            .unwrap()
    );

    let before = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    let mut connection = rusqlite::Connection::open(fixture.database.file.path()).unwrap();
    let tx = connection.transaction().unwrap();
    let dispatch: Vec<u8> = tx
        .query_row(
            "SELECT dispatch_attempt_id FROM provider_remote_request_intents WHERE taskrun_id=?1 AND taskrun_attempt_id=?2",
            rusqlite::params![fixture.taskrun_id.as_bytes(), fixture.claim_identity.attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let new_dispatch = [0x32_u8; 16];
    let new_call = [0x31_u8; 16];
    let new_permit = [0x33_u8; 16];
    tx.execute(
        "INSERT INTO provider_prepared_requests(call_id,prepared_digest,render_digest,profile_digest,record_digest)
         SELECT ?2,p.prepared_digest,p.render_digest,p.profile_digest,p.record_digest
         FROM provider_prepared_requests p JOIN provider_dispatch_attempts d USING(call_id)
         WHERE d.attempt_id=?1",
        rusqlite::params![dispatch, new_call.as_slice()],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO provider_dispatch_attempts(
           attempt_id,call_id,permit_id,token_reservation_id,cost_reservation_id,
           fencing_token,provider_idempotency_key,prepared_digest,render_digest,
           profile_digest,state,stream_id,settlement_digest,pre_effect_rejection)
         SELECT ?2,?3,?4,token_reservation_id,cost_reservation_id,fencing_token,
                'integrity-tamper-duplicate-intent',prepared_digest,render_digest,
                profile_digest,state,stream_id,settlement_digest,pre_effect_rejection
         FROM provider_dispatch_attempts WHERE attempt_id=?1",
        rusqlite::params![
            dispatch,
            new_dispatch.as_slice(),
            new_call.as_slice(),
            new_permit.as_slice()
        ],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO provider_remote_request_intents(
           dispatch_attempt_id,taskrun_id,taskrun_attempt_id,provider_id,profile_id,
           profile_digest,pricing_revision_digest,credential_realm,semantic_digest,
           prepared_digest,request_digest,runtime_authority_id,database_generation,
           runtime_generation,fencing_token,key_id,key_version,nonce,ciphertext,
           plaintext_len,plaintext_digest,created_at)
         SELECT ?2,taskrun_id,taskrun_attempt_id,provider_id,profile_id,profile_digest,
                pricing_revision_digest,credential_realm,semantic_digest,prepared_digest,
                request_digest,runtime_authority_id,database_generation,runtime_generation,
                fencing_token,key_id,key_version,nonce,ciphertext,plaintext_len,
                plaintext_digest,created_at
         FROM provider_remote_request_intents WHERE dispatch_attempt_id=?1",
        rusqlite::params![dispatch, new_dispatch.as_slice()],
    )
    .unwrap();
    tx.commit().unwrap();

    assert!(
        !repository
            .is_eligible(fixture.taskrun_id, fixture.version)
            .unwrap()
    );
    let after = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    assert_eq!(after.current_version, before.current_version);
    assert_eq!(
        after
            .events
            .iter()
            .map(|event| event.event_id())
            .collect::<Vec<_>>(),
        before
            .events
            .iter()
            .map(|event| event.event_id())
            .collect::<Vec<_>>()
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture
            .database
            .connection()))
        .is_err(),
        "validated reopen rejects the intentionally ambiguous remote intents"
    );
    let receipts: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_unknown_successor_receipts WHERE predecessor_taskrun_id=?1",
        rusqlite::params![fixture.taskrun_id.as_bytes()],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(receipts, 0);
}
