pub(super) const MIGRATION_V59: &str = r#"
CREATE TABLE provider_remote_terminal_settlements (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16 AND conversation_id!=zeroblob(16)),
 writer_owner_principal TEXT NOT NULL CHECK(length(writer_owner_principal) BETWEEN 1 AND 256),
 writer_fencing_token INTEGER NOT NULL CHECK(writer_fencing_token>0),
 begin_command_id BLOB NOT NULL CHECK(length(begin_command_id)=16 AND begin_command_id!=zeroblob(16)),
 generation_id BLOB NOT NULL CHECK(length(generation_id)=16 AND generation_id!=zeroblob(16)),
 begin_event_digest BLOB NOT NULL CHECK(length(begin_event_digest)=32 AND begin_event_digest!=zeroblob(32)),
 source_kind INTEGER NOT NULL CHECK(source_kind=2),
 terminal_status INTEGER NOT NULL CHECK(terminal_status IN (1,2,3,5)),
 publication_disposition INTEGER NOT NULL CHECK(publication_disposition BETWEEN 0 AND 5),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)),
 response_id_digest BLOB NOT NULL CHECK(length(response_id_digest)=32 AND response_id_digest!=zeroblob(32)),
 artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32 AND artifact_digest!=zeroblob(32)),
 published_output_digest BLOB CHECK(published_output_digest IS NULL OR (length(published_output_digest)=32 AND published_output_digest!=zeroblob(32))),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32 AND profile_digest!=zeroblob(32)),
 pricing_revision_digest BLOB NOT NULL CHECK(length(pricing_revision_digest)=32 AND pricing_revision_digest!=zeroblob(32)),
 runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id)=16 AND runtime_authority_id!=zeroblob(16)),
 database_generation INTEGER NOT NULL CHECK(database_generation>0),
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
 expected_taskrun_version INTEGER NOT NULL CHECK(expected_taskrun_version>0),
 settlement_state INTEGER NOT NULL CHECK(settlement_state IN (1,2,3,4,5)),
 input_tokens INTEGER CHECK(input_tokens IS NULL OR input_tokens>=0),
 output_tokens INTEGER CHECK(output_tokens IS NULL OR output_tokens>=0),
 cached_input_tokens INTEGER CHECK(cached_input_tokens IS NULL OR cached_input_tokens>=0),
 reasoning_output_tokens INTEGER CHECK(reasoning_output_tokens IS NULL OR reasoning_output_tokens>=0),
 charge_micros INTEGER CHECK(charge_micros IS NULL OR charge_micros>=0),
 currency TEXT CHECK(currency IS NULL OR length(currency)=3),
 settlement_digest BLOB CHECK(settlement_digest IS NULL OR (length(settlement_digest)=32 AND settlement_digest!=zeroblob(32))),
 application_receipt_digest BLOB CHECK(application_receipt_digest IS NULL OR (length(application_receipt_digest)=32 AND application_receipt_digest!=zeroblob(32))),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 CHECK((settlement_state IN (1,3,5) AND charge_micros IS NULL AND currency IS NULL AND settlement_digest IS NULL)
    OR (settlement_state IN (2,4) AND charge_micros IS NOT NULL AND currency IS NOT NULL AND settlement_digest IS NOT NULL)),
 CHECK((input_tokens IS NULL AND output_tokens IS NULL AND cached_input_tokens IS NULL AND reasoning_output_tokens IS NULL)
    OR (input_tokens IS NOT NULL AND output_tokens IS NOT NULL AND cached_input_tokens IS NOT NULL AND reasoning_output_tokens IS NOT NULL)),
 CHECK(settlement_state NOT IN (2,4) OR (input_tokens IS NOT NULL AND output_tokens IS NOT NULL AND cached_input_tokens IS NOT NULL AND reasoning_output_tokens IS NOT NULL)),
 CHECK((settlement_state NOT IN (4,5) AND application_receipt_digest IS NULL)
    OR (settlement_state IN (4,5) AND application_receipt_digest IS NOT NULL)),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_terminal_artifacts(dispatch_attempt_id)
);
CREATE TRIGGER provider_remote_terminal_settlements_identity_immutable
 BEFORE UPDATE ON provider_remote_terminal_settlements
 WHEN NEW.dispatch_attempt_id!=OLD.dispatch_attempt_id OR NEW.taskrun_id!=OLD.taskrun_id
 OR NEW.taskrun_attempt_id!=OLD.taskrun_attempt_id OR NEW.conversation_id!=OLD.conversation_id
 OR NEW.writer_owner_principal!=OLD.writer_owner_principal
 OR NEW.writer_fencing_token!=OLD.writer_fencing_token OR NEW.begin_command_id!=OLD.begin_command_id
 OR NEW.generation_id!=OLD.generation_id OR NEW.begin_event_digest!=OLD.begin_event_digest
 OR NEW.source_kind!=OLD.source_kind
 OR NEW.terminal_status!=OLD.terminal_status OR NEW.publication_disposition!=OLD.publication_disposition
 OR NEW.request_digest!=OLD.request_digest OR NEW.response_id_digest!=OLD.response_id_digest
 OR NEW.artifact_digest!=OLD.artifact_digest OR NEW.published_output_digest IS NOT OLD.published_output_digest OR NEW.profile_digest!=OLD.profile_digest
 OR NEW.pricing_revision_digest!=OLD.pricing_revision_digest
 OR NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.database_generation!=OLD.database_generation
 OR NEW.runtime_generation!=OLD.runtime_generation OR NEW.fencing_token!=OLD.fencing_token
 OR NEW.expected_taskrun_version!=OLD.expected_taskrun_version OR NEW.created_at!=OLD.created_at
 BEGIN SELECT RAISE(ABORT,'remote terminal settlement identity is immutable'); END;
CREATE TRIGGER provider_remote_terminal_settlements_no_delete
 BEFORE DELETE ON provider_remote_terminal_settlements
 BEGIN SELECT RAISE(ABORT,'remote terminal settlement is append only'); END;
CREATE TRIGGER provider_remote_terminal_settlements_state_transition
 BEFORE UPDATE ON provider_remote_terminal_settlements
 WHEN NOT ((OLD.settlement_state=1 AND NEW.settlement_state=2
            AND NEW.input_tokens IS OLD.input_tokens
            AND NEW.output_tokens IS OLD.output_tokens
            AND NEW.cached_input_tokens IS OLD.cached_input_tokens
            AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens
            AND OLD.charge_micros IS NULL AND OLD.currency IS NULL
            AND OLD.settlement_digest IS NULL)
        OR (OLD.settlement_state=1 AND NEW.settlement_state=3
            AND NEW.input_tokens IS OLD.input_tokens
            AND NEW.output_tokens IS OLD.output_tokens
            AND NEW.cached_input_tokens IS OLD.cached_input_tokens
            AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens
            AND NEW.charge_micros IS NULL AND NEW.currency IS NULL
            AND NEW.settlement_digest IS NULL)
        OR (OLD.settlement_state=1 AND NEW.settlement_state=5
            AND NEW.input_tokens IS OLD.input_tokens
            AND NEW.output_tokens IS OLD.output_tokens
            AND NEW.cached_input_tokens IS OLD.cached_input_tokens
            AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens
            AND NEW.charge_micros IS NULL AND NEW.currency IS NULL
            AND NEW.settlement_digest IS NULL)
        OR (OLD.settlement_state=3 AND NEW.settlement_state=5
            AND NEW.input_tokens IS OLD.input_tokens
            AND NEW.output_tokens IS OLD.output_tokens
            AND NEW.cached_input_tokens IS OLD.cached_input_tokens
            AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens
            AND NEW.charge_micros IS NULL AND NEW.currency IS NULL
            AND NEW.settlement_digest IS NULL)
        OR (OLD.settlement_state=2 AND NEW.settlement_state=4
            AND NEW.input_tokens IS OLD.input_tokens
            AND NEW.output_tokens IS OLD.output_tokens
            AND NEW.cached_input_tokens IS OLD.cached_input_tokens
            AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens
            AND NEW.charge_micros IS OLD.charge_micros
            AND NEW.currency IS OLD.currency
            AND NEW.settlement_digest IS OLD.settlement_digest))
 BEGIN SELECT RAISE(ABORT,'remote terminal settlement transition is invalid'); END;
"#;

pub(super) fn apply_v59_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V59)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("provider_remote_terminal_settlements", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(59)", [])?;
    tx.commit()
}

pub(super) fn v59_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 59..=71)
        || !v58_matches(connection, version)?
        || !table_sql_matches_migration(
            connection,
            "provider_remote_terminal_settlements",
            MIGRATION_V59,
        )?
    {
        return Ok(false);
    }
    let expected = [
        (
            "provider_remote_terminal_settlements_identity_immutable",
            "CREATE TRIGGER provider_remote_terminal_settlements_identity_immutable BEFORE UPDATE ON provider_remote_terminal_settlements WHEN NEW.dispatch_attempt_id!=OLD.dispatch_attempt_id OR NEW.taskrun_id!=OLD.taskrun_id OR NEW.taskrun_attempt_id!=OLD.taskrun_attempt_id OR NEW.conversation_id!=OLD.conversation_id OR NEW.writer_owner_principal!=OLD.writer_owner_principal OR NEW.writer_fencing_token!=OLD.writer_fencing_token OR NEW.begin_command_id!=OLD.begin_command_id OR NEW.generation_id!=OLD.generation_id OR NEW.begin_event_digest!=OLD.begin_event_digest OR NEW.source_kind!=OLD.source_kind OR NEW.terminal_status!=OLD.terminal_status OR NEW.publication_disposition!=OLD.publication_disposition OR NEW.request_digest!=OLD.request_digest OR NEW.response_id_digest!=OLD.response_id_digest OR NEW.artifact_digest!=OLD.artifact_digest OR NEW.published_output_digest IS NOT OLD.published_output_digest OR NEW.profile_digest!=OLD.profile_digest OR NEW.pricing_revision_digest!=OLD.pricing_revision_digest OR NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.database_generation!=OLD.database_generation OR NEW.runtime_generation!=OLD.runtime_generation OR NEW.fencing_token!=OLD.fencing_token OR NEW.expected_taskrun_version!=OLD.expected_taskrun_version OR NEW.created_at!=OLD.created_at BEGIN SELECT RAISE(ABORT,'remote terminal settlement identity is immutable'); END",
        ),
        (
            "provider_remote_terminal_settlements_no_delete",
            "CREATE TRIGGER provider_remote_terminal_settlements_no_delete BEFORE DELETE ON provider_remote_terminal_settlements BEGIN SELECT RAISE(ABORT,'remote terminal settlement is append only'); END",
        ),
        (
            "provider_remote_terminal_settlements_state_transition",
            "CREATE TRIGGER provider_remote_terminal_settlements_state_transition BEFORE UPDATE ON provider_remote_terminal_settlements WHEN NOT ((OLD.settlement_state=1 AND NEW.settlement_state=2 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND OLD.charge_micros IS NULL AND OLD.currency IS NULL AND OLD.settlement_digest IS NULL) OR (OLD.settlement_state=1 AND NEW.settlement_state=3 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND NEW.charge_micros IS NULL AND NEW.currency IS NULL AND NEW.settlement_digest IS NULL) OR (OLD.settlement_state=1 AND NEW.settlement_state=5 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND NEW.charge_micros IS NULL AND NEW.currency IS NULL AND NEW.settlement_digest IS NULL) OR (OLD.settlement_state=3 AND NEW.settlement_state=5 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND NEW.charge_micros IS NULL AND NEW.currency IS NULL AND NEW.settlement_digest IS NULL) OR (OLD.settlement_state=2 AND NEW.settlement_state=4 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND NEW.charge_micros IS OLD.charge_micros AND NEW.currency IS OLD.currency AND NEW.settlement_digest IS OLD.settlement_digest)) BEGIN SELECT RAISE(ABORT,'remote terminal settlement transition is invalid'); END",
        ),
    ];
    for (name, ddl) in expected {
        if !schema_trigger_matches(connection, name, ddl)? {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, ddl) = v12_fence_trigger("provider_remote_terminal_settlements", operation);
        if !schema_trigger_matches(connection, &name, &ddl)? {
            return Ok(false);
        }
    }
    Ok(v59_rows_match(connection)? && v59_remote_terminal_source_rows_match(connection)?)
}

pub(super) fn v59_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    _indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("provider_remote_terminal_settlements");
    triggers.extend([
        ("provider_remote_terminal_settlements_identity_immutable", "CREATE TRIGGER provider_remote_terminal_settlements_identity_immutable BEFORE UPDATE ON provider_remote_terminal_settlements WHEN NEW.dispatch_attempt_id!=OLD.dispatch_attempt_id OR NEW.taskrun_id!=OLD.taskrun_id OR NEW.taskrun_attempt_id!=OLD.taskrun_attempt_id OR NEW.conversation_id!=OLD.conversation_id OR NEW.writer_owner_principal!=OLD.writer_owner_principal OR NEW.writer_fencing_token!=OLD.writer_fencing_token OR NEW.begin_command_id!=OLD.begin_command_id OR NEW.generation_id!=OLD.generation_id OR NEW.begin_event_digest!=OLD.begin_event_digest OR NEW.source_kind!=OLD.source_kind OR NEW.terminal_status!=OLD.terminal_status OR NEW.publication_disposition!=OLD.publication_disposition OR NEW.request_digest!=OLD.request_digest OR NEW.response_id_digest!=OLD.response_id_digest OR NEW.artifact_digest!=OLD.artifact_digest OR NEW.profile_digest!=OLD.profile_digest OR NEW.pricing_revision_digest!=OLD.pricing_revision_digest OR NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.database_generation!=OLD.database_generation OR NEW.runtime_generation!=OLD.runtime_generation OR NEW.fencing_token!=OLD.fencing_token OR NEW.expected_taskrun_version!=OLD.expected_taskrun_version OR NEW.created_at!=OLD.created_at BEGIN SELECT RAISE(ABORT,'remote terminal settlement identity is immutable'); END"),
        ("provider_remote_terminal_settlements_no_delete", "CREATE TRIGGER provider_remote_terminal_settlements_no_delete BEFORE DELETE ON provider_remote_terminal_settlements BEGIN SELECT RAISE(ABORT,'remote terminal settlement is append only'); END"),
        ("provider_remote_terminal_settlements_state_transition", "CREATE TRIGGER provider_remote_terminal_settlements_state_transition BEFORE UPDATE ON provider_remote_terminal_settlements WHEN NOT ((OLD.settlement_state=1 AND NEW.settlement_state=2 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND OLD.charge_micros IS NULL AND OLD.currency IS NULL AND OLD.settlement_digest IS NULL) OR (OLD.settlement_state=1 AND NEW.settlement_state=3 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND NEW.charge_micros IS NULL AND NEW.currency IS NULL AND NEW.settlement_digest IS NULL) OR (OLD.settlement_state=1 AND NEW.settlement_state=5 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND NEW.charge_micros IS NULL AND NEW.currency IS NULL AND NEW.settlement_digest IS NULL) OR (OLD.settlement_state=3 AND NEW.settlement_state=5 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND NEW.charge_micros IS NULL AND NEW.currency IS NULL AND NEW.settlement_digest IS NULL) OR (OLD.settlement_state=2 AND NEW.settlement_state=4 AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens AND NEW.cached_input_tokens IS OLD.cached_input_tokens AND NEW.reasoning_output_tokens IS OLD.reasoning_output_tokens AND NEW.charge_micros IS OLD.charge_micros AND NEW.currency IS OLD.currency AND NEW.settlement_digest IS OLD.settlement_digest)) BEGIN SELECT RAISE(ABORT,'remote terminal settlement transition is invalid'); END"),
    ]);
    triggers.extend_from_slice(V59_FENCE_TRIGGERS);
}

const V59_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_provider_remote_terminal_settlements_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_settlements_insert\" AFTER INSERT ON \"provider_remote_terminal_settlements\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_terminal_settlements_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_settlements_update\" AFTER UPDATE ON \"provider_remote_terminal_settlements\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_terminal_settlements_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_settlements_delete\" AFTER DELETE ON \"provider_remote_terminal_settlements\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

fn v59_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_remote_terminal_settlements s
         LEFT JOIN provider_remote_terminal_artifacts a USING(dispatch_attempt_id)
         LEFT JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
         LEFT JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
         LEFT JOIN provider_dispatch_attempts d ON d.attempt_id=s.dispatch_attempt_id
         LEFT JOIN provider_accounting_settlements f USING(dispatch_attempt_id)
         LEFT JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
         LEFT JOIN provider_terminal_dispositions p USING(dispatch_attempt_id)
         WHERE a.dispatch_attempt_id IS NULL OR q.dispatch_attempt_id IS NULL
            OR r.dispatch_attempt_id IS NULL OR d.attempt_id IS NULL OR s.source_kind!=2
            OR s.taskrun_id!=q.taskrun_id OR s.taskrun_attempt_id!=q.taskrun_attempt_id
            OR s.request_digest!=q.request_digest OR s.response_id_digest!=r.plaintext_digest
            OR s.response_id_digest!=a.response_id_digest
            OR s.artifact_digest!=a.plaintext_digest OR s.terminal_status!=a.disposition
            OR (s.publication_disposition=0 AND s.terminal_status=1 AND (s.published_output_digest IS NULL OR s.published_output_digest=zeroblob(32)))
            OR ((s.publication_disposition!=0 OR s.terminal_status!=1) AND s.published_output_digest IS NOT NULL)
            OR s.profile_digest!=q.profile_digest OR s.pricing_revision_digest!=q.pricing_revision_digest
            OR s.profile_digest!=a.profile_digest OR s.pricing_revision_digest!=a.pricing_revision_digest
            OR s.runtime_authority_id!=q.runtime_authority_id
            OR s.database_generation!=q.database_generation
            OR s.runtime_generation!=q.runtime_generation OR s.fencing_token!=q.fencing_token
            OR (s.settlement_state IN (2,4) AND (f.dispatch_attempt_id IS NULL
                OR f.pricing_revision_digest!=s.pricing_revision_digest
                OR f.input_tokens IS NOT s.input_tokens OR f.output_tokens IS NOT s.output_tokens
                OR f.cached_input_tokens IS NOT s.cached_input_tokens
                OR f.reasoning_output_tokens IS NOT s.reasoning_output_tokens
                OR f.charge_micros IS NOT s.charge_micros OR f.currency IS NOT s.currency
                OR f.settlement_digest IS NOT s.settlement_digest))
            OR (s.settlement_state IN (1,3,5) AND (s.charge_micros IS NOT NULL
                OR s.currency IS NOT NULL OR s.settlement_digest IS NOT NULL))
            OR (s.settlement_state=2 AND s.publication_disposition=0
                AND (d.state NOT IN (4,6) OR (d.state=4 AND d.settlement_digest IS NOT s.settlement_digest)
                  OR (d.state=6 AND d.settlement_digest IS NOT NULL)
                  OR o.dispatch_attempt_id IS NULL OR p.dispatch_attempt_id IS NULL OR p.disposition!=1
                  OR o.terminal_sequence!=0 OR o.settlement_digest!=s.settlement_digest
                  OR o.plaintext_digest!=s.artifact_digest OR o.key_id!=a.key_id
                  OR o.key_version!=a.key_version OR o.nonce!=a.nonce
                  OR o.ciphertext!=a.ciphertext OR o.plaintext_len!=a.plaintext_len
                  OR o.state!=1 OR o.receipt_digest IS NOT NULL OR o.applied_at IS NOT NULL))
            OR (s.settlement_state=4 AND s.publication_disposition=0
                AND (d.state NOT IN (5,6) OR (d.state=5 AND d.settlement_digest IS NOT s.settlement_digest)
                  OR (d.state=6 AND d.settlement_digest IS NOT NULL)
                  OR o.dispatch_attempt_id IS NULL OR p.dispatch_attempt_id IS NULL OR p.disposition!=1
                  OR o.terminal_sequence!=0 OR o.settlement_digest!=s.settlement_digest
                  OR o.plaintext_digest!=s.artifact_digest OR o.key_id!=a.key_id
                  OR o.key_version!=a.key_version OR o.nonce!=a.nonce
                  OR o.ciphertext!=a.ciphertext OR o.plaintext_len!=a.plaintext_len
                  OR o.state!=2 OR o.receipt_digest IS NULL OR o.applied_at IS NULL
                  OR o.receipt_digest!=s.application_receipt_digest))
            OR (s.settlement_state IN (2,4) AND s.publication_disposition!=0
                AND o.dispatch_attempt_id IS NOT NULL)
            OR (s.settlement_state IN (2,4) AND (s.input_tokens IS NULL OR s.output_tokens IS NULL
                OR s.cached_input_tokens IS NULL OR s.reasoning_output_tokens IS NULL))
            OR s.terminal_status NOT IN (1,2,3,5)",
        [], |row| row.get(0),
    )?;
    Ok(invalid == 0)
}
