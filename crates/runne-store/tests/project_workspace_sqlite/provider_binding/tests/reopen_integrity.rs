use super::*;

#[test]
fn provider_binding_reopen_rejects_missing_claim_receipt() {
    let fixture = fixture("taskrun-provider-binding-missing-claim");
    bind(&fixture, 4, fixture.prepared.clone()).unwrap();
    let connection = fixture.database.connection();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER taskrun_claim_receipts_no_delete;")
        .unwrap();
    connection
        .execute(
            "DELETE FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![
                fixture.identity.taskrun_id.as_bytes(),
                fixture.identity.fence.0 as i64
            ],
        )
        .unwrap();
    connection.execute_batch("CREATE TRIGGER taskrun_claim_receipts_no_delete BEFORE DELETE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END;").unwrap();

    let rejected =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.database.reopen()));
    assert!(
        rejected.is_err(),
        "reopen admitted a binding without its claim receipt"
    );
}

#[test]
fn provider_binding_reopen_rejects_missing_dispatch_attempt() {
    let fixture = fixture("taskrun-provider-binding-missing-dispatch");
    bind(&fixture, 4, fixture.prepared.clone()).unwrap();
    let connection = fixture.database.connection();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection
        .execute(
            "DELETE FROM provider_dispatch_attempts WHERE call_id=?1",
            [fixture.prepared.call_id.as_bytes()],
        )
        .unwrap();

    let rejected =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.database.reopen()));
    assert!(
        rejected.is_err(),
        "reopen admitted a binding without its dispatch attempt"
    );
}
