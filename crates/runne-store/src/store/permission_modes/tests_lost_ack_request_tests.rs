//! These vectors guard cross-run request substitution and malformed replay data.
use super::*;
use runne_application::ports::{AggregateScope, OperationTag, PrincipalId};
use runne_domain::id::TaskRunId;

fn original() -> Request {
    let scope = IdempotencyScope {
        runtime_authority_id: RuntimeAuthorityId("fixture-authority".into()),
        principal_id: PrincipalId("fixture-principal".into()),
        operation: OperationTag::Complete,
        aggregate_scope: AggregateScope::ExistingTaskRun {
            taskrun_id: TaskRunId::from_bytes([
                1, 144, 0, 0, 0, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1,
            ]),
        },
    };
    Request {
        version: 1,
        run: [0x22; 16],
        command: [1, 144, 0, 0, 0, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2],
        key: "original-terminal".into(),
        scope: IdempotencyScopeCodec.encode(&scope).unwrap(),
        fingerprint: [0x44; 32],
    }
}

#[test]
fn retained_request_cannot_cross_run_or_accept_partial_extra_data() {
    let request = original();
    let bytes = serde_json::to_vec(&request).unwrap();
    let restored = Request::decode(&bytes, &[0x22; 16]).unwrap();
    assert_eq!(restored, request);
    assert_eq!(restored.command, [1, 144, 0, 0, 0, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2]);
    assert_eq!(restored.key, "original-terminal");
    assert_eq!(restored.fingerprint, [0x44; 32]);
    assert!(Request::decode(&bytes, &[0x23; 16]).is_err());
    for end in 0..bytes.len() {
        assert!(Request::decode(&bytes[..end], &[0x22; 16]).is_err());
    }
    let mut extra = bytes.clone();
    extra.extend_from_slice(b"{}");
    assert!(Request::decode(&extra, &[0x22; 16]).is_err());
    let mut unknown = serde_json::to_value(&request).unwrap();
    unknown["native_child"] = serde_json::json!(123);
    assert!(Request::decode(&serde_json::to_vec(&unknown).unwrap(), &[0x22; 16]).is_err());
    let mut duplicate = bytes;
    duplicate.pop();
    duplicate.extend_from_slice(b",\"version\":1}");
    assert!(Request::decode(&duplicate, &[0x22; 16]).is_err());
}

#[test]
fn replay_request_refuses_bad_scope_key_version_and_oversize() {
    for change in 0..7 {
        let mut request = original();
        match change {
            0 => request.version = 2,
            1 => request.key.clear(),
            2 => request.scope.clear(),
            3 => request.scope.push(0),
            4 => request.scope = vec![0; 4097],
            5 => request.key = "x".repeat(16385),
            6 => request.command = [0; 16],
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec(&request).unwrap();
        assert!(Request::decode(&bytes, &[0x22; 16]).is_err(), "vector {change}");
    }
    assert!(Request::decode(&vec![b' '; 16385], &[0x22; 16]).is_err());
}

#[test]
fn aggregate_ids_must_be_valid_even_when_scope_codec_roundtrips() {
    use runne_domain::id::{ConversationId, WorkspaceId};
    let valid = [1, 144, 0, 0, 0, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1];
    let variants = [
        AggregateScope::ExistingTaskRun { taskrun_id: TaskRunId::from_bytes(valid) },
        AggregateScope::ExistingConversation { conversation_id: ConversationId::from_bytes(valid) },
        AggregateScope::NewTaskRun {
            conversation_id: ConversationId::from_bytes(valid),
            workspace_id: WorkspaceId::from_bytes(valid),
        },
        AggregateScope::NewConversation {
            conversation_id: ConversationId::from_bytes(valid),
            workspace_id: WorkspaceId::from_bytes(valid),
        },
    ];
    for aggregate_scope in variants {
        let mut request = original();
        let mut scope = IdempotencyScopeCodec.decode(&request.scope).unwrap();
        scope.aggregate_scope = aggregate_scope;
        request.scope = IdempotencyScopeCodec.encode(&scope).unwrap();
        assert!(Request::decode(&serde_json::to_vec(&request).unwrap(), &[0x22; 16]).is_ok());
        let count = if matches!(scope.aggregate_scope,
            AggregateScope::NewTaskRun { .. } | AggregateScope::NewConversation { .. }) { 2 } else { 1 };
        for slot in 0..count {
            for bad in 0..3 {
                let mut damaged = request.clone();
                let start = damaged.scope.len() - 16 * (slot + 1);
                match bad {
                    0 => damaged.scope[start..start + 16].fill(0),
                    1 => damaged.scope[start + 6] = 0x40,
                    2 => damaged.scope[start + 8] = 0,
                    _ => unreachable!(),
                }
                assert!(IdempotencyScopeCodec.decode(&damaged.scope).is_ok());
                assert!(Request::decode(&serde_json::to_vec(&damaged).unwrap(), &[0x22; 16]).is_err());
            }
        }
    }
}

#[test]
fn original_command_adapter_preserves_all_lookup_identity_fields() {
    use runne_application::commands::CommandOutcome;
    let expected = original();
    let taskrun_id = TaskRunId::from_bytes([
        1, 144, 0, 0, 0, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1,
    ]);
    let payload = CommandCommit {
        command_id: CommandId::from_bytes(expected.command),
        idempotency_key: IdempotencyKey::new("original-terminal").unwrap(),
        idempotency_scope: IdempotencyScopeCodec.decode(&expected.scope).unwrap(),
        command_fingerprint: CommandFingerprint::from_bytes([0x44; 32]),
        expected_version: 9,
        events: vec![], // Identity extraction only; never a valid terminal commit.
        command_result: CommandOutcome::TaskRunCompleted { taskrun_id, new_version: 10 },
    };
    assert_eq!(Request::of(&payload, [0x22; 16]), expected);
}
