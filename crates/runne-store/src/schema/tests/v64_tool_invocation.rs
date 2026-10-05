#[test]
fn approved_tool_invocation_can_be_cancelled_before_claim() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO taskrun_tool_invocations (
            taskrun_id,attempt_id,cycle_id,proposal_index,expected_taskrun_version,
            call_id,tool_name,tool_revision,schema_digest,canonical_arguments,
            args_key_id,args_key_version,args_runtime_authority_id,args_database_generation,
            args_nonce,args_plaintext_len,args_plaintext_digest,arguments_digest,
            semantic_digest,effect_digest,source_refs,environment_id,environment_revision,
            root_identity,root_revision,target_name,approval_id,principal_id,
            approval_principal_id,approval_action,approval_resource,approval_digest,
            policy_revision,approval_expires_at,round_index,state,updated_at
        ) VALUES (
            zeroblob(16),zeroblob(16),zeroblob(16),0,7,'call-1','file.read','1',
            zeroblob(32),x'7b7d',zeroblob(16),1,zeroblob(16),1,zeroblob(12),2,
            zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),x'01','env','rev',
            zeroblob(32),1,'a',zeroblob(16),'principal','principal','file.read',
            'workspace:a',zeroblob(32),1,999,0,'approved',1
        );
        UPDATE taskrun_tool_invocations SET state='cancelled'
        WHERE call_id='call-1';",
        )
        .unwrap();
    let state: String = connection
        .query_row(
            "SELECT state FROM taskrun_tool_invocations WHERE call_id='call-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "cancelled");
}
