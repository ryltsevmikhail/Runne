//! Real Store lookup adapter regression; fresh reviewed disposable guest only.
//! No physical GO, terminal commit, lost ACK or process restart is claimed here.
use super::*;
use super::super::{ceremony, fixture, target};
use crate::codec::{CommandOutcomeCodec, StoreCodec};
use runne_application::permission_modes::PermissionMode;
use runne_application::ports::PrincipalId;

#[path = "tests_g2_corrupt_policy/lifecycle.rs"]
mod lifecycle;
#[path = "tests_terminal_retry_support.rs"]
mod support;

#[test]
fn real_receipt_lookup_preserves_identity_and_all_rows() {
    let owned = lifecycle::OwnedFixture::new();
    let f = owned.get();
    ceremony::commit(f, PermissionMode::RiskBased, 0);
    let (binding, prepared) = target::prepare(f);
    let task = binding.assignment().taskrun_id;
    // The source fixture creates this receipt by real submit, never direct INSERT.
    let (command, key, scope, fingerprint, outcome):
        (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = {
        let reader = f.store.inner.reader.lock().unwrap();
        reader.query_row(
            "SELECT c.command_id,c.idempotency_key,c.idempotency_scope_bytes,
                    c.fingerprint,c.command_outcome
             FROM command_receipts c JOIN events e ON e.command_id=c.command_id
             WHERE e.aggregate_id=?1 AND e.sequence=1",
            [task.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).unwrap()
    };
    let request = Request {
        version: 1,
        run: [0x25; 16],
        command: command.try_into().unwrap(),
        key: String::from_utf8(key).unwrap(),
        scope,
        fingerprint: fingerprint.try_into().unwrap(),
    };
    let original = Request::decode(&serde_json::to_vec(&request).unwrap(), &[0x25; 16]).unwrap();
    let expected = CommandOutcomeCodec.decode(&outcome).unwrap();
    assert!(matches!(expected,
        runne_application::commands::CommandOutcome::TaskRunSubmitted {
            taskrun_id, new_version: 2, ..
        } if taskrun_id == task));
    let before = support::snapshot(f);
    assert_eq!(original.lookup(&f.store, &f.scope.runtime_authority_id).unwrap(),
        ReceiptLookup::Duplicate { stored_result: expected.clone() });
    assert_eq!(support::snapshot(f), before);
    for field in 0..4 {
        let mut changed = original.clone();
        match field {
            0 => changed.command = uuid::Uuid::now_v7().into_bytes(),
            1 => changed.key = "changed-receipt-key".into(),
            2 => {
                let mut scope = IdempotencyScopeCodec.decode(&changed.scope).unwrap();
                scope.principal_id = PrincipalId("different-principal".into());
                changed.scope = IdempotencyScopeCodec.encode(&scope).unwrap();
            }
            3 => changed.fingerprint[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(matches!(changed.lookup(&f.store, &f.scope.runtime_authority_id),
            Err(CommitError::IdempotencyConflict { .. })), "identity field {field}");
        assert_eq!(support::snapshot(f), before);
    }
    let mut missing = original.clone();
    missing.command = uuid::Uuid::now_v7().into_bytes();
    missing.key = "absent-receipt-key".into();
    assert_eq!(missing.lookup(&f.store, &f.scope.runtime_authority_id).unwrap(), ReceiptLookup::Miss);
    assert_eq!(support::snapshot(f), before);
    assert_eq!(original.lookup(&f.store, &f.scope.runtime_authority_id).unwrap(),
        ReceiptLookup::Duplicate { stored_result: expected });
    assert_eq!(support::snapshot(f), before);
    drop(prepared);
    drop(owned); // Checked fallible RAM disposal after all fixture handles.
}
