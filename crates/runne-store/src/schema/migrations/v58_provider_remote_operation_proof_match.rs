pub(super) fn v58_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_remote_operation_proofs p
         LEFT JOIN provider_remote_request_intents q ON q.dispatch_attempt_id=p.dispatch_attempt_id
         LEFT JOIN provider_remote_response_bindings r ON r.dispatch_attempt_id=p.dispatch_attempt_id
         WHERE q.dispatch_attempt_id IS NULL OR r.dispatch_attempt_id IS NULL
           OR p.taskrun_id!=q.taskrun_id OR p.taskrun_id!=r.taskrun_id
           OR p.taskrun_attempt_id!=q.taskrun_attempt_id OR p.taskrun_attempt_id!=r.taskrun_attempt_id
           OR p.provider_id!=q.provider_id OR p.provider_id!=r.provider_id
           OR p.credential_realm!=q.credential_realm OR p.credential_realm!=r.credential_realm
           OR p.profile_id!=q.profile_id OR p.profile_id!=r.profile_id
           OR p.profile_digest!=q.profile_digest OR p.profile_digest!=r.profile_digest
           OR p.pricing_revision_digest!=q.pricing_revision_digest OR p.pricing_revision_digest!=r.pricing_revision_digest
           OR p.request_digest!=q.request_digest OR p.request_digest!=r.request_digest
           OR p.response_id_digest!=r.plaintext_digest
           OR p.runtime_authority_id!=q.runtime_authority_id OR p.runtime_authority_id!=r.runtime_authority_id
           OR p.database_generation!=q.database_generation OR p.database_generation!=r.database_generation
           OR p.key_id!=q.key_id OR p.key_id!=r.key_id OR p.key_version!=q.key_version OR p.key_version!=r.key_version
           OR (p.state=2 AND p.observation_status IS NULL AND NOT EXISTS(
                 SELECT 1 FROM provider_remote_terminal_artifacts t
                 WHERE t.dispatch_attempt_id=p.dispatch_attempt_id))
           OR (p.state=3 AND p.observation_status IS NOT NULL)
           OR (p.operation=3 AND NOT EXISTS(
             SELECT 1 FROM taskrun_provider_cancel_fences c
             WHERE c.taskrun_id=p.taskrun_id AND c.taskrun_attempt_id=p.taskrun_attempt_id
               AND c.dispatch_attempt_id=p.dispatch_attempt_id))
           OR length(p.nonce)!=16 OR p.nonce=zeroblob(16)",
        [],
        |row| row.get(0),
    )?;
    Ok(invalid == 0)
}
