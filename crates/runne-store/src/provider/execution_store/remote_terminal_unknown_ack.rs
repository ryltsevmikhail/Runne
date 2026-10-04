struct UnknownOutboxAckRow {
    receipt_outbox: Option<Vec<u8>>,
    commitment: Vec<u8>,
    disposition: i64,
    output_key: Option<Vec<u8>>,
    output_key_version: Option<i64>,
    output_nonce: Option<Vec<u8>>,
    output_ciphertext: Option<Vec<u8>>,
    output_len: Option<i64>,
    output_digest: Option<Vec<u8>>,
    receipt_application_key: Option<String>,
    outbox_attempt: Vec<u8>,
    outbox_sequence: i64,
    outbox_key: Vec<u8>,
    outbox_key_version: i64,
    outbox_nonce: Vec<u8>,
    outbox_ciphertext: Vec<u8>,
    outbox_len: i64,
    outbox_digest: Vec<u8>,
    outbox_commitment: Vec<u8>,
    outbox_application_key: String,
    outbox_state: i64,
    outbox_ack: Option<Vec<u8>>,
    attempt_state: i64,
    attempt_commitment: Option<Vec<u8>>,
    has_known_accounting: bool,
    has_known_disposition: bool,
    has_remote_source: bool,
}

fn validate_unknown_terminal_outbox_ack(
    connection: &Connection,
    outbox_id: [u8; 16],
    attempt_id: [u8; 16],
    commitment: [u8; 32],
    expected_ack: Option<[u8; 32]>,
) -> Result<bool, ProviderExecutionError> {
    let row: Option<UnknownOutboxAckRow> = connection
        .query_row(
            "SELECT r.outbox_id,r.unknown_commitment,r.terminal_disposition,
                    r.output_key_id,r.output_key_version,r.output_nonce,r.output_ciphertext,
                    r.output_plaintext_len,r.output_digest,r.application_idempotency_key,
                    x.dispatch_attempt_id,x.terminal_sequence,x.key_id,x.key_version,x.nonce,
                    x.ciphertext,x.plaintext_len,x.plaintext_digest,x.settlement_digest,
                    x.application_idempotency_key,x.state,x.receipt_digest,d.state,d.settlement_digest,
                    EXISTS(SELECT 1 FROM provider_accounting_settlements s
                           WHERE s.dispatch_attempt_id=d.attempt_id),
                    EXISTS(SELECT 1 FROM provider_terminal_dispositions m
                           WHERE m.dispatch_attempt_id=d.attempt_id),
                    EXISTS(SELECT 1 FROM provider_remote_terminal_settlements z
                           WHERE z.dispatch_attempt_id=d.attempt_id)
             FROM provider_unknown_terminal_receipts r
             JOIN provider_terminal_outbox x ON x.outbox_id=r.outbox_id
             JOIN provider_dispatch_attempts d ON d.attempt_id=r.dispatch_attempt_id
             WHERE r.dispatch_attempt_id=?1",
            [attempt_id.as_slice()],
            |row| {
                Ok(UnknownOutboxAckRow {
                    receipt_outbox: row.get(0)?,
                    commitment: row.get(1)?,
                    disposition: row.get(2)?,
                    output_key: row.get(3)?,
                    output_key_version: row.get(4)?,
                    output_nonce: row.get(5)?,
                    output_ciphertext: row.get(6)?,
                    output_len: row.get(7)?,
                    output_digest: row.get(8)?,
                    receipt_application_key: row.get(9)?,
                    outbox_attempt: row.get(10)?,
                    outbox_sequence: row.get(11)?,
                    outbox_key: row.get(12)?,
                    outbox_key_version: row.get(13)?,
                    outbox_nonce: row.get(14)?,
                    outbox_ciphertext: row.get(15)?,
                    outbox_len: row.get(16)?,
                    outbox_digest: row.get(17)?,
                    outbox_commitment: row.get(18)?,
                    outbox_application_key: row.get(19)?,
                    outbox_state: row.get(20)?,
                    outbox_ack: row.get(21)?,
                    attempt_state: row.get(22)?,
                    attempt_commitment: row.get(23)?,
                    has_known_accounting: row.get(24)?,
                    has_known_disposition: row.get(25)?,
                    has_remote_source: row.get(26)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let Some(row) = row else {
        let misplaced: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_unknown_terminal_receipts
                               WHERE outbox_id=?1 OR dispatch_attempt_id=?2)",
                params![outbox_id.as_slice(), attempt_id.as_slice()],
                |value| value.get(0),
            )
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        return if misplaced {
            Err(ProviderExecutionError::JournalCorrupt)
        } else {
            Ok(false)
        };
    };
    let output_matches = row.output_key.as_deref() == Some(row.outbox_key.as_slice())
        && row.output_key_version == Some(row.outbox_key_version)
        && row.output_nonce.as_deref() == Some(row.outbox_nonce.as_slice())
        && row.output_ciphertext.as_deref() == Some(row.outbox_ciphertext.as_slice())
        && row.output_len == Some(row.outbox_len)
        && row.output_digest.as_deref() == Some(row.outbox_digest.as_slice());
    let ack_matches = match (row.outbox_state, row.outbox_ack.as_deref(), expected_ack) {
        (1, None, None) => true,
        (2, Some(stored), Some(expected)) => stored == expected,
        _ => false,
    };
    if row.receipt_outbox.as_deref() != Some(outbox_id.as_slice())
        || unknown_fixed_bytes::<32>(row.commitment)? != commitment
        || row.disposition != 1
        || !output_matches
        || row.outbox_attempt.as_slice() != attempt_id.as_slice()
        || row.outbox_sequence <= 0
        || unknown_fixed_bytes::<32>(row.outbox_commitment)? != commitment
        || row.receipt_application_key.as_deref() != Some(row.outbox_application_key.as_str())
        || row.outbox_application_key.is_empty()
        || !matches!(row.attempt_state, 4 | 5)
        || row.attempt_commitment.as_deref() != Some(commitment.as_slice())
        || row.has_known_accounting
        || row.has_known_disposition
        || row.has_remote_source
        || !ack_matches
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(true)
}
