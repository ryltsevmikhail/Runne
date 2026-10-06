use super::*;
use runne_domain::id::{AttemptId, CycleId, TaskRunId};

#[test]
fn release_permission_tracks_current_selection_revision_and_mode() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    crate::schema::apply_migrations(&connection).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    let binding = binding();
    insert_permission(&connection, &binding, ToolPermissionDecisionSource::Human);
    let tx = connection.unchecked_transaction().unwrap();
    assert!(matches!(
        validate_release_permission(&tx, "runtime-a", &binding, 50),
        Err(ToolInvocationStoreError::Conflict)
    ));
    tx.execute(
        "INSERT INTO permission_mode_selections(
           runtime_authority_id,principal_id,workspace_id,project_id,selected_mode,preset_version,
           authorization_revision,managed_policy_version,managed_policy_digest,
           expires_at_unix_ms,last_command_id,intent_digest,updated_at_unix_ms
         ) VALUES('runtime-a','submitter',?1,zeroblob(16),1,1,1,0,?2,NULL,?3,?2,51)",
        params![
            binding_workspace().as_bytes(),
            MISSING_PERMISSION_MODE_MANAGED_DIGEST.to_vec(),
            vec![4u8; 16]
        ],
    )
    .unwrap();
    assert_eq!(
        validate_release_permission(&tx, "runtime-a", &binding, 51).unwrap(),
        ToolPermissionDecisionSource::Human
    );
    tx.execute(
        "UPDATE permission_mode_selections SET selected_mode=2,authorization_revision=2",
        [],
    )
    .unwrap();
    assert!(matches!(
        validate_release_permission(&tx, "runtime-a", &binding, 52),
        Err(ToolInvocationStoreError::Conflict)
    ));
    tx.commit().unwrap();
}

#[test]
fn missing_permission_admission_fails_closed() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    crate::schema::apply_migrations(&connection).unwrap();
    let tx = connection.unchecked_transaction().unwrap();
    assert!(matches!(
        validate_release_permission(&tx, "runtime-a", &binding(), 50),
        Err(ToolInvocationStoreError::InvalidState)
    ));
}

fn insert_permission(
    connection: &rusqlite::Connection,
    binding: &ToolInvocationBindingV1,
    source: ToolPermissionDecisionSource,
) {
    connection
        .execute(
            "INSERT INTO taskrun_tool_permission_admissions(
               taskrun_id,attempt_id,cycle_id,proposal_index,runtime_authority_id,principal_id,
               workspace_id,selected_mode,preset_version,authorization_revision,
               managed_policy_version,managed_policy_digest,composite_scope_digest,containment,
               native_scope_handle,decision_source,relevant_policy_digest,expires_at_unix_ms,
               created_at_unix_ms
             ) VALUES(?1,?2,?3,?4,'runtime-a','submitter',?5,1,1,1,0,?6,?7,1,?8,?9,?6,100,49)",
            params![
                binding.key.taskrun_id.as_bytes(),
                binding.key.attempt_id.as_bytes(),
                binding.key.cycle_id.as_bytes(),
                binding.key.proposal_index,
                binding_workspace().as_bytes(),
                MISSING_PERMISSION_MODE_MANAGED_DIGEST.to_vec(),
                vec![2u8; 32],
                vec![3u8; 32],
                source.tag()
            ],
        )
        .unwrap();
}

fn binding_workspace() -> runne_domain::id::WorkspaceId {
    runne_domain::id::WorkspaceId::from_bytes([5; 16])
}

fn binding() -> ToolInvocationBindingV1 {
    let mut value = ToolInvocationBindingV1 {
        key: ToolInvocationKey {
            taskrun_id: TaskRunId::from_bytes([1; 16]),
            attempt_id: AttemptId::from_bytes([2; 16]),
            cycle_id: CycleId::from_bytes([3; 16]),
            proposal_index: 4,
        },
        expected_taskrun_version: 5,
        call_id: "call-a".into(),
        tool_name: "workspace.file.read".into(),
        tool_revision: "1".into(),
        schema_digest: IntegrityDigest::from_bytes([6; 32]),
        canonical_arguments: br#"{"path":"file.txt"}"#.to_vec(),
        arguments_digest: IntegrityDigest::from_bytes([0; 32]),
        semantic_digest: IntegrityDigest::from_bytes([0; 32]),
        sources: vec![ToolSourceRef {
            dispatch_attempt_id: [7; 16],
            sequence: 1,
            event_kind: 5,
            terminal: true,
            plaintext_digest: IntegrityDigest::from_bytes([8; 32]),
            profile_digest: IntegrityDigest::from_bytes([9; 32]),
            runtime_generation: 1,
        }],
        environment_id: "linux-agent-tools-v1".into(),
        environment_revision: "1".into(),
        root_identity: IntegrityDigest::from_bytes([10; 32]),
        root_revision: 1,
        target_name: "file.txt".into(),
        target_precondition: None,
        approval_id: [11; 16],
        principal_id: "submitter".into(),
        approval_principal_id: "submitter".into(),
        approval_action: "workspace.tool.invoke".into(),
        approval_resource: "workspace:file.txt".into(),
        approval_digest: IntegrityDigest::from_bytes([12; 32]),
        policy_revision: 1,
        approval_expires_at: 100,
        round_index: 0,
    };
    value.refresh_digests();
    value
}
