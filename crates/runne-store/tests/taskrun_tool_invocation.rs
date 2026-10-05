use std::sync::Arc;

use runne_application::{
    ports::{ExecutionNodeId, RuntimeAuthorityId, TaskRunAssignmentIdentity, TaskRunFence},
    prohibited_content::{
        CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
    },
    provider::{ProviderEncryptedPayload, ProviderJournalKeyBinding},
};
use runne_domain::id::{AttemptId, CycleId, IntegrityDigest, TaskRunId};
use runne_store::store::taskrun_tool_invocation::{
    EncryptedToolPayloadV1, ToolInvocationBindingV1, ToolInvocationKey, ToolInvocationStoreError,
    ToolSourceRef,
};

#[path = "support/validated_reopen.rs"]
mod validated_reopen;

struct Guard;
impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

#[test]
fn tool_invocation_store_reopens_canonical_sqlite_and_rejects_unsubmitted_task() {
    let database = validated_reopen::ValidatedTestDatabase::new("tool-invocation");
    let authority = RuntimeAuthorityId("tool-loop-test-runtime".into());
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(Guard);
    let taskrun = task_id::<TaskRunId>("018f2e3a-7000-7000-8000-000000000001");
    let attempt = task_id::<AttemptId>("018f2e3a-7000-7000-8000-000000000002");
    let cycle = task_id::<CycleId>("018f2e3a-7000-7000-8000-000000000003");
    let binding = fixture_binding(taskrun, attempt, cycle);
    let identity = validated_reopen::initialize_database_identity(database.path()).unwrap();
    runne_store::schema::open_existing_read_only(database.as_path()).unwrap();
    {
        let store = validated_reopen::reopen_store(
            database.path(),
            identity,
            authority.clone(),
            guard.clone(),
        )
        .unwrap();
        let assignment = TaskRunAssignmentIdentity {
            taskrun_id: taskrun,
            attempt_id: attempt,
            node_id: ExecutionNodeId("linux-test-node".into()),
            node_epoch: 1,
            fence: TaskRunFence(1),
        };
        assert!(matches!(
            store.propose_taskrun_tool_invocation(
                binding.clone(),
                encrypted_args(&binding),
                &assignment,
                1
            ),
            Err(ToolInvocationStoreError::StaleVersion)
        ));
        assert_eq!(
            store
                .get_taskrun_tool_invocation(ToolInvocationKey {
                    taskrun_id: taskrun,
                    attempt_id: attempt,
                    cycle_id: cycle,
                    proposal_index: 0
                })
                .unwrap(),
            None
        );
    }
    let reopened =
        validated_reopen::reopen_store(database.path(), identity, authority, guard).unwrap();
    assert_eq!(
        reopened
            .get_taskrun_tool_invocation(ToolInvocationKey {
                taskrun_id: taskrun,
                attempt_id: attempt,
                cycle_id: cycle,
                proposal_index: 0
            })
            .unwrap(),
        None
    );
}

fn encrypted_args(binding: &ToolInvocationBindingV1) -> EncryptedToolPayloadV1 {
    EncryptedToolPayloadV1 {
        key: ProviderJournalKeyBinding::new([1; 16], 1, [2; 16], 1).unwrap(),
        payload: ProviderEncryptedPayload::new(
            [3; 12],
            vec![0; binding.canonical_arguments.len() + 16],
            binding.canonical_arguments.len() as u64,
            binding.arguments_digest.into_bytes(),
        )
        .unwrap(),
    }
}

fn fixture_binding(
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    cycle_id: CycleId,
) -> ToolInvocationBindingV1 {
    let zero = IntegrityDigest::from_bytes([7; 32]);
    let mut value = ToolInvocationBindingV1 {
        key: ToolInvocationKey {
            taskrun_id,
            attempt_id,
            cycle_id,
            proposal_index: 0,
        },
        expected_taskrun_version: 4,
        call_id: "call-a".into(),
        tool_name: "file.read".into(),
        tool_revision: "1".into(),
        schema_digest: zero,
        canonical_arguments: br#"{"name":"file.txt"}"#.to_vec(),
        arguments_digest: zero,
        semantic_digest: zero,
        sources: vec![ToolSourceRef {
            dispatch_attempt_id: [8; 16],
            sequence: 1,
            event_kind: 1,
            terminal: true,
            plaintext_digest: zero,
            profile_digest: zero,
            runtime_generation: 1,
        }],
        environment_id: "workspace-1".into(),
        environment_revision: "rev-1".into(),
        root_identity: zero,
        root_revision: 1,
        target_name: "file.txt".into(),
        target_precondition: None,
        approval_id: [9; 16],
        principal_id: "submitter".into(),
        approval_principal_id: "approver".into(),
        approval_action: "file.read".into(),
        approval_resource: "workspace:file.txt".into(),
        approval_digest: zero,
        policy_revision: 1,
        approval_expires_at: 100,
        round_index: 0,
    };
    value.refresh_digests();
    value
}

fn task_id<T: std::str::FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}
