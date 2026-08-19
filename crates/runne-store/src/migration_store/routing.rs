impl MigrationRoutingStore for SqliteMigrationControlStore {
    fn load_runtime_binding(
        &self,
        aggregate_id: AggregateId,
        routing_unit: &RoutingUnit,
    ) -> Result<Option<RuntimeBinding>, MigrationStoreError> {
        let connection = self.reader()?;
        load_runtime_binding_on(&connection, &aggregate_id, routing_unit)
    }

    fn load_dispatch_intent(
        &self,
        aggregate_id: AggregateId,
    ) -> Result<Option<RoutingDispatchIntent>, MigrationStoreError> {
        let connection = self.reader()?;
        load_dispatch_intent_on(&connection, &aggregate_id)
    }

    fn bind_and_create_dispatch_intent(
        &self,
        request: BindRuntimeRequest,
    ) -> Result<RouteAdmission, MigrationStoreError> {
        validate_bind_runtime_request(&request)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)?;
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_write_error)?;

        if let Some(binding) =
            load_runtime_binding_on(&transaction, &request.aggregate_id, &request.routing_unit)?
        {
            let intent = load_dispatch_intent_on(&transaction, &request.aggregate_id)?
                .ok_or(MigrationStoreError::IntegrityViolation)?;
            validate_existing_intent(&intent, &request)?;
            transaction.commit().map_err(map_write_error)?;
            return Ok(RouteAdmission::Existing { binding, intent });
        }

        let durable_snapshot = load_routing_head_on(&transaction, &request.routing_unit)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        if durable_snapshot.routing_generation != request.expected_snapshot.routing_generation {
            return Err(MigrationStoreError::RoutingGenerationConflict {
                expected: request.expected_snapshot.routing_generation,
                actual: durable_snapshot.routing_generation,
            });
        }
        if durable_snapshot != request.expected_snapshot {
            return Err(MigrationStoreError::IntegrityViolation);
        }

        let selected_authority = match &request.fallback_policy {
            PreDispatchFallbackPolicy::Disabled => durable_snapshot.authority.clone(),
            PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance { source_profile } => {
                if !matches!(durable_snapshot.authority, RuntimeAuthority::Candidate(_))
                    || source_profile != &request.routing_unit.feature_profile
                {
                    return Err(MigrationStoreError::IntegrityViolation);
                }
                RuntimeAuthority::Source(durable_snapshot.source.clone())
            }
        };
        let runtime_generation = match &selected_authority {
            RuntimeAuthority::Source(generation) | RuntimeAuthority::Candidate(generation) => {
                generation.clone()
            }
        };
        let binding = RuntimeBinding::new(
            request.aggregate_id.clone(),
            selected_authority,
            runtime_generation,
            durable_snapshot.routing_generation,
            durable_snapshot.fencing_token,
            request.bound_at,
        )
        .map_err(|_| MigrationStoreError::IntegrityViolation)?;
        let intent = RoutingDispatchIntent {
            aggregate_id: request.aggregate_id.clone(),
            command_id: request.command_id,
            idempotency_key: request.idempotency_key.clone(),
            request_digest: request.request_digest,
            status: DispatchIntentStatus::Pending,
            created_at: request.bound_at,
            updated_at: request.bound_at,
        };
        let (aggregate_type, aggregate_bytes) = aggregate_parts(&request.aggregate_id)?;
        let binding_blob = encode_runtime_binding(&binding).map_err(map_codec_error)?;
        transaction
            .execute(
                "INSERT INTO runtime_bindings
                 (aggregate_type, aggregate_id, routing_unit_digest,
                  routing_generation, binding_blob)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    aggregate_type,
                    aggregate_bytes.as_slice(),
                    request.routing_unit.digest().as_bytes().as_slice(),
                    u64_to_i64(binding.routing_generation.get())?,
                    binding_blob,
                ],
            )
            .map_err(map_runtime_binding_write_error)?;
        transaction
            .execute(
                "INSERT INTO routing_dispatch_intents
                 (aggregate_type, aggregate_id, command_id, idempotency_key,
                  request_digest, dispatch_status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    aggregate_type,
                    aggregate_bytes.as_slice(),
                    request.command_id.as_bytes().as_slice(),
                    request.idempotency_key.as_str().as_bytes(),
                    request.request_digest.as_bytes().as_slice(),
                    dispatch_status_tag(DispatchIntentStatus::Pending),
                    request.bound_at.as_unix_micros(),
                    request.bound_at.as_unix_micros(),
                ],
            )
            .map_err(map_dispatch_intent_write_error)?;
        transaction.commit().map_err(map_write_error)?;
        Ok(RouteAdmission::Created { binding, intent })
    }

    fn claim_dispatch(
        &self,
        aggregate_id: AggregateId,
        command_id: CommandId,
        claimed_at: Timestamp,
    ) -> Result<DispatchClaim, MigrationStoreError> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)?;
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_write_error)?;
        let current = load_dispatch_intent_on(&transaction, &aggregate_id)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        if current.command_id != command_id {
            return Err(MigrationStoreError::DispatchIntentConflict);
        }
        if current.status != DispatchIntentStatus::Pending {
            transaction.commit().map_err(map_write_error)?;
            return Ok(DispatchClaim::Existing(current));
        }
        if claimed_at < current.updated_at {
            return Err(MigrationStoreError::InvalidDispatchTransition);
        }
        let (aggregate_type, aggregate_bytes) = aggregate_parts(&aggregate_id)?;
        let changed = transaction
            .execute(
                "UPDATE routing_dispatch_intents
                 SET dispatch_status = ?1, updated_at = ?2
                 WHERE aggregate_type = ?3
                   AND aggregate_id = ?4
                   AND command_id = ?5
                   AND dispatch_status = ?6",
                params![
                    dispatch_status_tag(DispatchIntentStatus::Indeterminate),
                    claimed_at.as_unix_micros(),
                    aggregate_type,
                    aggregate_bytes.as_slice(),
                    command_id.as_bytes().as_slice(),
                    dispatch_status_tag(DispatchIntentStatus::Pending),
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(MigrationStoreError::InvalidDispatchTransition);
        }
        let claimed = load_dispatch_intent_on(&transaction, &aggregate_id)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        transaction.commit().map_err(map_write_error)?;
        Ok(DispatchClaim::Claimed(claimed))
    }

    fn record_dispatch_result(
        &self,
        aggregate_id: AggregateId,
        command_id: CommandId,
        status: DispatchResultStatus,
        recorded_at: Timestamp,
    ) -> Result<RoutingDispatchIntent, MigrationStoreError> {
        let target = match status {
            DispatchResultStatus::Accepted => DispatchIntentStatus::Accepted,
            DispatchResultStatus::RejectedBeforeAcceptance => {
                DispatchIntentStatus::RejectedBeforeAcceptance
            }
        };
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)?;
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_write_error)?;
        let current = load_dispatch_intent_on(&transaction, &aggregate_id)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        if current.command_id != command_id {
            return Err(MigrationStoreError::DispatchIntentConflict);
        }
        if current.status == target {
            transaction.commit().map_err(map_write_error)?;
            return Ok(current);
        }
        if current.status != DispatchIntentStatus::Indeterminate || recorded_at < current.updated_at
        {
            return Err(MigrationStoreError::InvalidDispatchTransition);
        }
        let (aggregate_type, aggregate_bytes) = aggregate_parts(&aggregate_id)?;
        let changed = transaction
            .execute(
                "UPDATE routing_dispatch_intents
                 SET dispatch_status = ?1, updated_at = ?2
                 WHERE aggregate_type = ?3
                   AND aggregate_id = ?4
                   AND command_id = ?5
                   AND dispatch_status = ?6",
                params![
                    dispatch_status_tag(target),
                    recorded_at.as_unix_micros(),
                    aggregate_type,
                    aggregate_bytes.as_slice(),
                    command_id.as_bytes().as_slice(),
                    dispatch_status_tag(DispatchIntentStatus::Indeterminate),
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(MigrationStoreError::InvalidDispatchTransition);
        }
        let recorded = load_dispatch_intent_on(&transaction, &aggregate_id)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        transaction.commit().map_err(map_write_error)?;
        Ok(recorded)
    }
}
