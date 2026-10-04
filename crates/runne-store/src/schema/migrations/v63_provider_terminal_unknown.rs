pub(super) const MIGRATION_V63: &str = r#"
CREATE TABLE provider_unknown_terminal_receipts (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16 AND conversation_id!=zeroblob(16)),
 terminal_sequence INTEGER NOT NULL CHECK(terminal_sequence>0),
 terminal_disposition INTEGER NOT NULL CHECK(terminal_disposition IN (1,2,3)),
 accounting_reason INTEGER NOT NULL CHECK(accounting_reason IN (1,2,3,4)),
 usage_present INTEGER NOT NULL CHECK(usage_present IN (0,1)),
 input_tokens INTEGER CHECK(input_tokens IS NULL OR input_tokens>=0),
 output_tokens INTEGER CHECK(output_tokens IS NULL OR output_tokens>=0),
 cached_input_tokens INTEGER CHECK(cached_input_tokens IS NULL OR cached_input_tokens>=0),
 reasoning_output_tokens INTEGER CHECK(reasoning_output_tokens IS NULL OR reasoning_output_tokens>=0),
 journal_digest BLOB NOT NULL CHECK(length(journal_digest)=32 AND journal_digest!=zeroblob(32)),
 source_binding_digest BLOB NOT NULL CHECK(length(source_binding_digest)=32 AND source_binding_digest!=zeroblob(32)),
 writer_owner_id TEXT NOT NULL CHECK(length(writer_owner_id)>0),
 writer_lease_digest BLOB NOT NULL CHECK(length(writer_lease_digest)=32 AND writer_lease_digest!=zeroblob(32)),
 authority_id BLOB NOT NULL CHECK(length(authority_id)=16 AND authority_id!=zeroblob(16)),
 authority_revision INTEGER NOT NULL CHECK(authority_revision>0),
 grant_digest BLOB CHECK(grant_digest IS NULL OR (length(grant_digest)=32 AND grant_digest!=zeroblob(32))),
 runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id)=16 AND runtime_authority_id!=zeroblob(16)),
 database_generation INTEGER NOT NULL CHECK(database_generation>0),
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32 AND profile_digest!=zeroblob(32)),
 pricing_revision_digest BLOB NOT NULL CHECK(length(pricing_revision_digest)=32 AND pricing_revision_digest!=zeroblob(32)),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)),
 begin_receipt_digest BLOB NOT NULL CHECK(length(begin_receipt_digest)=32 AND begin_receipt_digest!=zeroblob(32)),
 started_receipt_digest BLOB NOT NULL CHECK(length(started_receipt_digest)=32 AND started_receipt_digest!=zeroblob(32)),
 claim_receipt_digest BLOB CHECK(claim_receipt_digest IS NULL OR (length(claim_receipt_digest)=32 AND claim_receipt_digest!=zeroblob(32))),
 admission_digest BLOB NOT NULL CHECK(length(admission_digest)=32 AND admission_digest!=zeroblob(32)),
 taskrun_history_digest BLOB NOT NULL CHECK(length(taskrun_history_digest)=32 AND taskrun_history_digest!=zeroblob(32)),
 conversation_history_digest BLOB NOT NULL CHECK(length(conversation_history_digest)=32 AND conversation_history_digest!=zeroblob(32)),
 taskrun_stream_version INTEGER NOT NULL CHECK(taskrun_stream_version>0),
 conversation_stream_version INTEGER NOT NULL CHECK(conversation_stream_version>0),
 call_digest_version INTEGER NOT NULL CHECK(call_digest_version IN (1,2)),
 publication_allowed INTEGER NOT NULL CHECK(publication_allowed IN (0,1)),
 principal_id TEXT NOT NULL CHECK(length(principal_id)>0),
 provider_id TEXT NOT NULL CHECK(length(provider_id)>0),
 provider_idempotency_key TEXT NOT NULL CHECK(length(provider_idempotency_key)>0),
 admission_currency TEXT NOT NULL CHECK(length(admission_currency)>0),
 reserve_token_id BLOB NOT NULL CHECK(length(reserve_token_id)=16 AND reserve_token_id!=zeroblob(16)),
 reserve_token_amount INTEGER NOT NULL CHECK(reserve_token_amount>0),
 reserve_cost_id BLOB NOT NULL CHECK(length(reserve_cost_id)=16 AND reserve_cost_id!=zeroblob(16)),
 reserve_cost_amount INTEGER NOT NULL CHECK(reserve_cost_amount>0),
 output_key_id BLOB CHECK(output_key_id IS NULL OR (length(output_key_id)=16 AND output_key_id!=zeroblob(16))),
 output_key_version INTEGER CHECK(output_key_version IS NULL OR output_key_version>0),
 output_nonce BLOB CHECK(output_nonce IS NULL OR length(output_nonce)=12),
 output_ciphertext BLOB CHECK(output_ciphertext IS NULL OR length(output_ciphertext) BETWEEN 16 AND 4194304),
 output_plaintext_len INTEGER CHECK(output_plaintext_len IS NULL OR output_plaintext_len BETWEEN 0 AND 65536),
 outbox_id BLOB CHECK(outbox_id IS NULL OR (length(outbox_id)=16 AND outbox_id!=zeroblob(16))),
 output_digest BLOB CHECK(output_digest IS NULL OR (length(output_digest)=32 AND output_digest!=zeroblob(32))),
 application_idempotency_key TEXT CHECK(application_idempotency_key IS NULL OR length(application_idempotency_key)>0),
 unknown_commitment BLOB NOT NULL CHECK(length(unknown_commitment)=32 AND unknown_commitment!=zeroblob(32)),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 CHECK(reserve_token_id!=reserve_cost_id),
 CHECK((usage_present=0 AND accounting_reason=1 AND input_tokens IS NULL AND output_tokens IS NULL
   AND cached_input_tokens IS NULL AND reasoning_output_tokens IS NULL)
   OR (usage_present=1 AND accounting_reason IN (2,3,4) AND input_tokens IS NOT NULL
   AND output_tokens IS NOT NULL AND cached_input_tokens IS NOT NULL AND reasoning_output_tokens IS NOT NULL)),
 CHECK(usage_present=0 OR (cached_input_tokens<=input_tokens
   AND reasoning_output_tokens<=output_tokens)),
 CHECK((terminal_disposition=1 AND output_key_id IS NOT NULL AND output_key_version IS NOT NULL
   AND output_nonce IS NOT NULL AND output_ciphertext IS NOT NULL AND output_plaintext_len IS NOT NULL
   AND output_digest IS NOT NULL AND
   ((outbox_id IS NOT NULL AND application_idempotency_key IS NOT NULL)
    OR (outbox_id IS NULL AND application_idempotency_key IS NULL)))
   OR (terminal_disposition IN (2,3) AND output_key_id IS NULL AND output_key_version IS NULL
   AND output_nonce IS NULL AND output_ciphertext IS NULL AND output_plaintext_len IS NULL
   AND output_digest IS NULL
   AND outbox_id IS NULL AND output_digest IS NULL AND application_idempotency_key IS NULL)),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_dispatch_attempts(attempt_id),
 FOREIGN KEY(output_key_id,output_key_version) REFERENCES provider_journal_key_refs(key_id,key_version),
 FOREIGN KEY(output_key_id,output_key_version,output_nonce) REFERENCES provider_encryption_nonces(key_id,key_version,nonce),
 FOREIGN KEY(outbox_id) REFERENCES provider_terminal_outbox(outbox_id)
);
CREATE TRIGGER provider_unknown_terminal_receipts_immutable BEFORE UPDATE ON provider_unknown_terminal_receipts BEGIN SELECT RAISE(ABORT,'unknown terminal receipt is append only'); END;
CREATE TRIGGER provider_unknown_terminal_receipts_no_delete BEFORE DELETE ON provider_unknown_terminal_receipts BEGIN SELECT RAISE(ABORT,'unknown terminal receipt is append only'); END;
"#;

pub(super) fn apply_v63_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V63)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("provider_unknown_terminal_receipts", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(63)", [])?;
    tx.commit()
}

pub(super) fn v63_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 63
        || !v62_matches(connection, 62)?
        || !table_sql_matches_migration(
            connection,
            "provider_unknown_terminal_receipts",
            MIGRATION_V63,
        )?
    {
        return Ok(false);
    }
    for (name, expected) in V63_RECEIPT_TRIGGERS {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("provider_unknown_terminal_receipts", operation);
        if !schema_trigger_matches(connection, &name, &expected)? {
            return Ok(false);
        }
    }
    v63_unknown_receipts_match(connection)
}

pub(super) fn v63_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("provider_unknown_terminal_receipts");
    triggers.extend_from_slice(V63_RECEIPT_TRIGGERS);
    triggers.extend_from_slice(V63_FENCE_TRIGGERS);
}

const V63_RECEIPT_TRIGGERS: &[(&str, &str)] = &[
    (
        "provider_unknown_terminal_receipts_immutable",
        "CREATE TRIGGER provider_unknown_terminal_receipts_immutable BEFORE UPDATE ON provider_unknown_terminal_receipts BEGIN SELECT RAISE(ABORT,'unknown terminal receipt is append only'); END",
    ),
    (
        "provider_unknown_terminal_receipts_no_delete",
        "CREATE TRIGGER provider_unknown_terminal_receipts_no_delete BEFORE DELETE ON provider_unknown_terminal_receipts BEGIN SELECT RAISE(ABORT,'unknown terminal receipt is append only'); END",
    ),
];

const V63_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_provider_unknown_terminal_receipts_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_unknown_terminal_receipts_insert\" AFTER INSERT ON \"provider_unknown_terminal_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_unknown_terminal_receipts_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_unknown_terminal_receipts_update\" AFTER UPDATE ON \"provider_unknown_terminal_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_unknown_terminal_receipts_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_unknown_terminal_receipts_delete\" AFTER DELETE ON \"provider_unknown_terminal_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

include!("v63_provider_terminal_unknown_match.rs");
