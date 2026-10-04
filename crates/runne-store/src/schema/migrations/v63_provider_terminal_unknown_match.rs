fn v63_unknown_receipts_match(connection: &Connection) -> SqliteResult<bool> {
    let invalid: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM provider_unknown_terminal_receipts r
           LEFT JOIN provider_execution_admissions a
             ON a.dispatch_attempt_id=r.dispatch_attempt_id
           LEFT JOIN provider_dispatch_attempts d
             ON d.attempt_id=r.dispatch_attempt_id
           LEFT JOIN provider_prepared_requests p ON p.call_id=a.call_id
           LEFT JOIN provider_online_dispatch_claim_providers c
             ON c.dispatch_attempt_id=r.dispatch_attempt_id
           LEFT JOIN provider_online_dispatch_issuance_evidence i
             ON i.dispatch_attempt_id=r.dispatch_attempt_id
           LEFT JOIN provider_terminal_outbox x ON x.outbox_id=r.outbox_id
           WHERE a.dispatch_attempt_id IS NULL OR d.attempt_id IS NULL
             OR a.taskrun_id!=r.taskrun_id
             OR a.execution_attempt_id!=r.taskrun_attempt_id
             OR a.conversation_id!=r.conversation_id
             OR a.runtime_authority_id!=r.runtime_authority_id
             OR a.authority_id!=r.authority_id OR a.authority_revision!=r.authority_revision
             OR a.generation!=r.runtime_generation
             OR a.fencing_token!=r.fencing_token
             OR a.profile_digest!=r.profile_digest
             OR a.pricing_revision_digest!=r.pricing_revision_digest
             OR a.currency!=r.admission_currency
             OR a.token_reservation_id!=r.reserve_token_id
             OR a.cost_reservation_id!=r.reserve_cost_id
             OR a.provider_idempotency_key!=r.provider_idempotency_key
             OR p.call_id IS NULL OR p.record_digest!=r.request_digest
             OR c.dispatch_attempt_id IS NULL OR c.provider_id!=r.provider_id
             OR i.dispatch_attempt_id IS NULL OR i.provider_id!=r.provider_id
             OR i.authority_id!=r.authority_id OR i.authority_revision!=r.authority_revision
             OR i.journal_runtime_authority_id!=r.runtime_authority_id
             OR i.journal_database_generation!=r.database_generation
             OR d.state NOT IN (4,5) OR d.settlement_digest!=r.unknown_commitment
             OR EXISTS(SELECT 1 FROM provider_accounting_settlements s
                       WHERE s.dispatch_attempt_id=r.dispatch_attempt_id)
             OR EXISTS(SELECT 1 FROM provider_terminal_dispositions m
                       WHERE m.dispatch_attempt_id=r.dispatch_attempt_id)
             OR (r.terminal_disposition=1 AND NOT EXISTS(
                   SELECT 1 FROM provider_journal_key_refs k
                   JOIN provider_encryption_nonces n
                     ON n.key_id=k.key_id AND n.key_version=k.key_version
                   WHERE k.key_id=r.output_key_id AND k.key_version=r.output_key_version
                     AND k.runtime_authority_id=r.runtime_authority_id
                     AND k.database_generation=r.database_generation
                     AND n.nonce=r.output_nonce AND n.purpose=2
                     AND n.dispatch_attempt_id=r.dispatch_attempt_id AND n.sequence IS NULL))
             OR (r.outbox_id IS NOT NULL AND (
                   x.outbox_id IS NULL OR x.dispatch_attempt_id!=r.dispatch_attempt_id
                   OR x.terminal_sequence!=r.terminal_sequence OR x.state NOT IN (1,2)
                   OR x.settlement_digest!=r.unknown_commitment
                   OR x.application_idempotency_key!=r.application_idempotency_key
                   OR x.plaintext_digest!=r.output_digest
                   OR x.key_id!=r.output_key_id OR x.key_version!=r.output_key_version
                   OR x.nonce!=r.output_nonce OR x.ciphertext!=r.output_ciphertext
                   OR x.plaintext_len!=r.output_plaintext_len))
             OR (r.outbox_id IS NULL AND EXISTS(
                   SELECT 1 FROM provider_terminal_outbox q
                   WHERE q.dispatch_attempt_id=r.dispatch_attempt_id))
             OR (r.terminal_disposition IN (2,3) AND x.outbox_id IS NOT NULL)
             OR NOT EXISTS(SELECT 1 FROM provider_budget_reservations b
                           WHERE b.reservation_id=r.reserve_token_id
                             AND b.provider_idempotency_key=r.provider_idempotency_key
                             AND b.dimension=1 AND b.amount=r.reserve_token_amount
                             AND b.state=1 AND b.settled_amount IS NULL AND b.released_at IS NULL)
             OR NOT EXISTS(SELECT 1 FROM provider_budget_reservations b
                           WHERE b.reservation_id=r.reserve_cost_id
                             AND b.provider_idempotency_key=r.provider_idempotency_key
                             AND b.dimension=2 AND b.amount=r.reserve_cost_amount
                             AND b.state=1 AND b.settled_amount IS NULL AND b.released_at IS NULL)
             OR (SELECT COUNT(*) FROM provider_budget_reservations b
                 WHERE b.provider_idempotency_key=r.provider_idempotency_key)!=2
             OR (r.usage_present=1 AND (
                   r.cached_input_tokens>r.input_tokens
                   OR r.reasoning_output_tokens>r.output_tokens))
         )",
        [],
        |row| row.get(0),
    )?;
    Ok(!invalid)
}
