//! Fresh receipt-only recovery roles; no native authority reconstruction.
use super::{Context, Intent, Request, read, success_recovery};
use crate::store::StoreTransaction;
use runne_application::ports::{CommitError, ReceiptLookup, RuntimeAuthorityId};
use std::{path::Path, sync::Arc};

pub(super) fn run(root: &Path, context: &Context, conflict: bool) {
    let intent: Intent = read(root, "intent-ready.json");
    intent.trust.check(root, context.authority);
    let result = success_recovery::recover(success_recovery::RecoveryInput {
        database: context.database(),
        original_request: &intent.request,
        run_nonce: context.run,
        controller_pid: context.controller,
        writer_pid: intent.writer,
        expected_outcome: intent.expected(),
    });
    let observed = result.unwrap();
    assert_eq!(observed.outcome, intent.expected());
    assert_eq!(observed.recovery_pid, std::process::id());
    if conflict {
        reject_changed_key(context, &intent);
    }
    intent.trust.check(root, context.authority);
}

fn reject_changed_key(context: &Context, intent: &Intent) {
    let authority = RuntimeAuthorityId(hex::encode(context.authority));
    let (path, writer, reader) = context.database().open().unwrap();
    let store = StoreTransaction::open_with_connections(
        path.to_str().unwrap(),
        writer,
        reader,
        authority.clone(),
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let original = Request::decode(&intent.request, &context.run).unwrap();
    let expected = ReceiptLookup::Duplicate {
        stored_result: intent.expected(),
    };
    assert_eq!(original.lookup(&store, &authority).unwrap(), expected);
    let mut changed: serde_json::Value = serde_json::from_slice(&intent.request).unwrap();
    changed["key"] = serde_json::Value::String("lost-ack-conflicting-key".into());
    let changed = Request::decode(&serde_json::to_vec(&changed).unwrap(), &context.run).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            changed.lookup(&store, &authority),
            Err(CommitError::IdempotencyConflict { .. })
        ));
    }
    assert_eq!(original.lookup(&store, &authority).unwrap(), expected);
    drop(store);
}
