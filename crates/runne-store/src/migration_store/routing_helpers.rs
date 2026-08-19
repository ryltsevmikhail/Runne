fn receipt_scope(context: &MigrationCommandContext) -> Result<Vec<u8>, MigrationStoreError> {
    let operator = context.operator_id.as_str().as_bytes();
    let length =
        u16::try_from(operator.len()).map_err(|_| MigrationStoreError::ArithmeticOverflow)?;
    let mut scope = b"runne-migration-scope\x01".to_vec();
    scope.extend_from_slice(&length.to_be_bytes());
    scope.extend_from_slice(operator);
    Ok(scope)
}

fn validate_bind_runtime_request(request: &BindRuntimeRequest) -> Result<(), MigrationStoreError> {
    if matches!(request.aggregate_id, AggregateId::Workspace(_))
        || request.request_digest.as_bytes() == &[0; 32]
        || !snapshot_matches_unit(&request.expected_snapshot, &request.routing_unit)
        || request.bound_at < request.expected_snapshot.committed_at
    {
        return Err(MigrationStoreError::IntegrityViolation);
    }
    Ok(())
}

fn validate_existing_intent(
    intent: &RoutingDispatchIntent,
    request: &BindRuntimeRequest,
) -> Result<(), MigrationStoreError> {
    if intent.aggregate_id != request.aggregate_id
        || intent.command_id != request.command_id
        || intent.idempotency_key != request.idempotency_key
        || intent.request_digest != request.request_digest
    {
        return Err(MigrationStoreError::DispatchIntentConflict);
    }
    Ok(())
}

fn load_routing_head_on(
    connection: &Connection,
    unit: &RoutingUnit,
) -> Result<Option<RoutingSnapshot>, MigrationStoreError> {
    let unit_digest = unit.digest();
    let row: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT h.routing_generation, s.snapshot_blob
             FROM routing_head h
             JOIN routing_snapshots s
               ON s.routing_unit_digest = h.routing_unit_digest
              AND s.routing_generation = h.routing_generation
             WHERE h.routing_unit_digest = ?1",
            [unit_digest.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_read_error)?;
    let Some((stored_generation, snapshot_blob)) = row else {
        return Ok(None);
    };
    let snapshot = decode_routing_snapshot(&snapshot_blob).map_err(map_codec_error)?;
    if stored_generation != u64_to_i64(snapshot.routing_generation.get())?
        || !snapshot_matches_unit(&snapshot, unit)
    {
        return Err(MigrationStoreError::CorruptData);
    }
    Ok(Some(snapshot))
}

fn load_runtime_binding_on(
    connection: &Connection,
    aggregate_id: &AggregateId,
    routing_unit: &RoutingUnit,
) -> Result<Option<RuntimeBinding>, MigrationStoreError> {
    let (aggregate_type, aggregate_bytes) = aggregate_parts(aggregate_id)?;
    let row: Option<StoredRuntimeBindingRow> = connection
        .query_row(
            "SELECT b.routing_unit_digest, b.routing_generation, b.binding_blob,
                    s.snapshot_blob
             FROM runtime_bindings b
             JOIN routing_snapshots s
               ON s.routing_unit_digest = b.routing_unit_digest
              AND s.routing_generation = b.routing_generation
             WHERE b.aggregate_type = ?1 AND b.aggregate_id = ?2",
            params![aggregate_type, aggregate_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(map_read_error)?;
    let Some((stored_unit_digest, stored_generation, binding_blob, snapshot_blob)) = row else {
        return Ok(None);
    };
    if stored_unit_digest != routing_unit.digest().as_bytes() {
        return Err(MigrationStoreError::RuntimeBindingConflict);
    }
    let binding = decode_runtime_binding(&binding_blob).map_err(map_codec_error)?;
    let snapshot = decode_routing_snapshot(&snapshot_blob).map_err(map_codec_error)?;
    if &binding.aggregate_id != aggregate_id
        || stored_generation != u64_to_i64(binding.routing_generation.get())?
        || !snapshot_matches_unit(&snapshot, routing_unit)
        || binding.routing_generation != snapshot.routing_generation
        || binding.authority != snapshot.authority
        || binding.fencing_token != snapshot.fencing_token
        || binding.bound_at < snapshot.committed_at
    {
        return Err(MigrationStoreError::CorruptData);
    }
    Ok(Some(binding))
}

type StoredRuntimeBindingRow = (Vec<u8>, i64, Vec<u8>, Vec<u8>);

fn load_dispatch_intent_on(
    connection: &Connection,
    aggregate_id: &AggregateId,
) -> Result<Option<RoutingDispatchIntent>, MigrationStoreError> {
    let (aggregate_type, aggregate_bytes) = aggregate_parts(aggregate_id)?;
    let row: Option<StoredDispatchIntentRow> = connection
        .query_row(
            "SELECT command_id, idempotency_key, request_digest,
                    dispatch_status, created_at, updated_at
             FROM routing_dispatch_intents
             WHERE aggregate_type = ?1 AND aggregate_id = ?2",
            params![aggregate_type, aggregate_bytes.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(map_read_error)?;
    let Some((command_bytes, idempotency_bytes, digest_bytes, status, created_at, updated_at)) =
        row
    else {
        return Ok(None);
    };
    let command_id = decode_command_id(&command_bytes)?;
    let idempotency_key = std::str::from_utf8(&idempotency_bytes)
        .map_err(|_| MigrationStoreError::CorruptData)
        .and_then(|value| {
            IdempotencyKey::new(value.to_owned()).map_err(|_| MigrationStoreError::CorruptData)
        })?;
    let request_digest = ArtifactDigest::from_bytes(
        digest_bytes
            .try_into()
            .map_err(|_| MigrationStoreError::CorruptData)?,
    );
    if request_digest.as_bytes() == &[0; 32] || updated_at < created_at {
        return Err(MigrationStoreError::CorruptData);
    }
    Ok(Some(RoutingDispatchIntent {
        aggregate_id: aggregate_id.clone(),
        command_id,
        idempotency_key,
        request_digest,
        status: decode_dispatch_status(status)?,
        created_at: Timestamp::from_unix_micros(created_at),
        updated_at: Timestamp::from_unix_micros(updated_at),
    }))
}

type StoredDispatchIntentRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64);
