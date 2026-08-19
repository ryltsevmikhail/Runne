fn lookup_receipt_on(
    connection: &Connection,
    context: &MigrationCommandContext,
    fingerprint: &MigrationCommandFingerprint,
) -> Result<MigrationReceiptLookup, MigrationStoreError> {
    let by_command: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT idempotency_key, fingerprint, outcome_blob
             FROM migration_receipts
             WHERE command_id = ?1",
            [context.command_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(map_read_error)?;
    if let Some((stored_key, stored_fingerprint, outcome_blob)) = by_command {
        if stored_key != context.idempotency_key.as_str().as_bytes()
            || stored_fingerprint != fingerprint.as_bytes()
        {
            return Err(MigrationStoreError::IdempotencyConflict);
        }
        return Ok(MigrationReceiptLookup::Duplicate {
            stored_result: Box::new(
                decode_migration_outcome(&outcome_blob).map_err(map_codec_error)?,
            ),
        });
    }

    let conflicting_scope_key: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM migration_receipts
                 WHERE scope_bytes = ?1 AND idempotency_key = ?2
             )",
            params![
                receipt_scope(context)?,
                context.idempotency_key.as_str().as_bytes()
            ],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    if conflicting_scope_key {
        Err(MigrationStoreError::IdempotencyConflict)
    } else {
        Ok(MigrationReceiptLookup::Miss)
    }
}
