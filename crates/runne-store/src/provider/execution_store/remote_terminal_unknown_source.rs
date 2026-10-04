fn load_unknown_source_rows(
    connection: &Connection,
    attempt: &ExecutionAttempt,
    proof: Option<&OnlineEffectProofCapabilitySet>,
) -> Result<UnknownSourceRows, ProviderExecutionError> {
    if let Some(proof) = proof {
        crate::store::test_support_diagnostics::on_error(
            "unknown.original_issuance",
            verify_unknown_original_issuance(connection, attempt, proof),
        )?;
    }
    let admission = connection
        .query_row(
            "SELECT a.taskrun_id,a.execution_attempt_id,a.conversation_id,a.principal_id,
                    a.provider_idempotency_key,a.authority_id,a.authority_revision,
                    a.runtime_authority_id,a.database_generation,a.generation,a.fencing_token,
                    a.profile_digest,a.pricing_revision_digest,a.currency,p.record_digest,
                    c.provider_id,e.owner_id,e.attempt_id,e.permit_id,e.fencing_token,
                    a.token_reservation_id,a.cost_reservation_id,a.owner_id
             FROM provider_execution_admissions a
             JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
              AND d.call_id=a.call_id AND d.permit_id=a.permit_id
              AND d.provider_idempotency_key=a.provider_idempotency_key
              AND d.fencing_token=a.fencing_token
              AND d.prepared_digest=a.prepared_digest AND d.render_digest=a.render_digest
              AND d.profile_digest=a.profile_digest
              AND d.token_reservation_id=a.token_reservation_id
              AND d.cost_reservation_id=a.cost_reservation_id
             JOIN provider_prepared_requests p ON p.call_id=a.call_id
              AND p.prepared_digest=a.prepared_digest AND p.render_digest=a.render_digest
              AND p.profile_digest=a.profile_digest
             JOIN provider_online_dispatch_claim_providers c
               ON c.dispatch_attempt_id=d.attempt_id
             JOIN provider_online_dispatch_issuance_evidence i
               ON i.dispatch_attempt_id=d.attempt_id AND i.provider_id=c.provider_id
              AND i.authority_id=a.authority_id AND i.authority_revision=a.authority_revision
              AND i.journal_runtime_authority_id=a.runtime_authority_id
              AND i.journal_database_generation=a.database_generation
             JOIN provider_effect_authorities e ON e.authority_id=a.authority_id
               AND e.revision=a.authority_revision AND e.attempt_id=d.attempt_id
              AND e.permit_id=a.permit_id AND e.token_reservation_id=a.token_reservation_id
              AND e.cost_reservation_id=a.cost_reservation_id
              AND e.prepared_digest=a.prepared_digest AND e.render_digest=a.render_digest
              AND e.profile_digest=a.profile_digest AND e.fencing_token=a.fencing_token
              AND e.owner_id=a.owner_id
             WHERE a.dispatch_attempt_id=?1 AND d.attempt_id=?1",
            [attempt.dispatch_attempt_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, Vec<u8>>(17)?,
                    row.get::<_, Vec<u8>>(18)?,
                    row.get::<_, i64>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                    row.get::<_, Vec<u8>>(21)?,
                    row.get::<_, String>(22)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let taskrun_id = TaskRunId::from_bytes(unknown_fixed_bytes(admission.0.clone())?);
    let taskrun_attempt_id = AttemptId::from_bytes(unknown_fixed_bytes(admission.1.clone())?);
    let conversation_id = ConversationId::from_bytes(unknown_fixed_bytes(admission.2.clone())?);
    let authority_id = unknown_fixed_bytes(admission.5.clone())?;
    let authority_revision = unknown_positive_u64(admission.6)?;
    let runtime_authority_id = unknown_fixed_bytes(admission.7.clone())?;
    let database_generation = unknown_positive_u64(admission.8)?;
    let runtime_generation = unknown_positive_u64(admission.9)?;
    let fencing_token = unknown_positive_u64(admission.10)?;
    let profile_digest = unknown_fixed_bytes(admission.11.clone())?;
    let pricing_revision_digest = unknown_fixed_bytes(admission.12.clone())?;
    let request_digest = unknown_fixed_bytes(admission.14.clone())?;
    if unknown_fixed_bytes::<16>(admission.17.clone())? != *attempt.dispatch_attempt_id.as_bytes()
        || unknown_positive_u64(admission.19)? != attempt.fencing_token
        || runtime_authority_id != attempt.runtime_authority_id
        || database_generation != attempt.database_generation
        || runtime_generation != attempt.generation
        || fencing_token != attempt.fencing_token
        || profile_digest != attempt.profile_digest
        || pricing_revision_digest != attempt.pricing_revision_digest
        || request_digest == [0; 32]
        || admission.3.is_empty()
        || admission.4 != attempt.provider_idempotency_key
        || admission.13 != attempt.currency
        || admission.16.is_empty()
        || admission.22 != admission.16
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let original = crate::store::test_support_diagnostics::on_error(
        "unknown.original_history",
        load_unknown_original_history(
            connection,
            taskrun_id,
            taskrun_attempt_id,
            conversation_id,
            &admission.3,
            attempt,
        ),
    )?;
    let original_effect = load_unknown_original_effect(connection, attempt, &admission.15, proof)?;
    let mut reserve_statement = connection
        .prepare(
            "SELECT reservation_id,dimension,amount,state,settled_amount,released_at
         FROM provider_budget_reservations WHERE provider_idempotency_key=?1 ORDER BY dimension",
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let reserve_rows = reserve_statement
        .query_map([&attempt.provider_idempotency_key], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
            ))
        })
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if reserve_rows.len() != 2
        || reserve_rows[0].1 != 1
        || reserve_rows[1].1 != 2
        || reserve_rows
            .iter()
            .any(|row| row.3 != 1 || row.4.is_some() || row.5.is_some())
    {
        return Err(ProviderExecutionError::ReservationMismatch);
    }
    let ids = (
        unknown_fixed_bytes(admission.20.clone())?,
        unknown_fixed_bytes(admission.21.clone())?,
    );
    if unknown_fixed_bytes::<16>(reserve_rows[0].0.clone())? != ids.0
        || unknown_fixed_bytes::<16>(reserve_rows[1].0.clone())? != ids.1
    {
        return Err(ProviderExecutionError::ReservationMismatch);
    }
    let (token_amount, cost_amount) = (
        unknown_positive_u64(reserve_rows[0].2)?,
        unknown_positive_u64(reserve_rows[1].2)?,
    );
    let reservations = [
        ProviderUnknownReservationSnapshot {
            reservation_id: ids.0,
            dimension: 1,
            reserved_amount: token_amount,
            settled_amount: None,
            held: true,
        },
        ProviderUnknownReservationSnapshot {
            reservation_id: ids.1,
            dimension: 2,
            reserved_amount: cost_amount,
            settled_amount: None,
            held: true,
        },
    ];
    let (grant_digest, grant_active) = unknown_grant_binding(
        connection,
        UnknownGrantExpectation {
            attempt_id: attempt.dispatch_attempt_id,
            provider_id: &admission.15,
            provider_idempotency_key: &admission.4,
            owner_id: &admission.16,
            runtime_authority_id,
            database_generation,
            profile_digest,
            pricing_revision_digest,
        },
    )?;
    let mut writer_hash = Sha256::new();
    writer_hash.update(b"GOCODE_PROVIDER_UNKNOWN_WRITER_PIN_V1\0");
    writer_hash.update(admission.16.as_bytes());
    writer_hash.update(admission.5.as_slice());
    writer_hash.update(admission.6.to_be_bytes());
    writer_hash.update(admission.17.as_slice());
    writer_hash.update(admission.18.as_slice());
    writer_hash.update(admission.19.to_be_bytes());
    let writer_digest: [u8; 32] = writer_hash.finalize().into();
    let mut admission_hash = Sha256::new();
    admission_hash.update(b"GOCODE_PROVIDER_UNKNOWN_ADMISSION_V1\0");
    for field in [
        admission.0.as_slice(),
        admission.1.as_slice(),
        admission.2.as_slice(),
        admission.3.as_bytes(),
        admission.4.as_bytes(),
        admission.5.as_slice(),
        admission.7.as_slice(),
        admission.11.as_slice(),
        admission.12.as_slice(),
        admission.13.as_bytes(),
        admission.14.as_slice(),
        admission.20.as_slice(),
        admission.21.as_slice(),
    ] {
        admission_hash.update((field.len() as u64).to_be_bytes());
        admission_hash.update(field);
    }
    let admission_digest: [u8; 32] = admission_hash.finalize().into();
    let original = ProviderUnknownTerminalOriginalBinding {
        runtime_authority_id,
        writer_owner_id: admission.16.clone(),
        writer_lease_digest: writer_digest,
        authority_revision,
        grant_digest,
        database_generation,
        runtime_generation,
        dispatch_attempt_id: attempt.dispatch_attempt_id,
        taskrun_id,
        execution_attempt_id: taskrun_attempt_id,
        conversation_id,
        principal_id: admission.3.clone(),
        provider_id: admission.15.clone(),
        provider_idempotency_key: admission.4.clone(),
        request_digest,
        begin_receipt_digest: original.0,
        started_receipt_digest: original.1,
        claim_receipt_digest: original.2,
        admission_digest,
        committed_effect_digest: original_effect.digest(),
        taskrun_history_digest: original.3,
        conversation_history_digest: original.4,
        taskrun_stream_version: original.5,
        conversation_stream_version: original.6,
        profile_digest,
        pricing_revision_digest,
        admission_currency: admission.13.clone(),
        call_digest_version: attempt.call_digest_version,
        fencing_token,
        publication_allowed: true,
        reservations,
    };
    let current = load_unknown_current_facts(
        connection,
        UnknownCurrentExpectation {
            taskrun_id,
            taskrun_attempt_id,
            conversation_id,
            attempt,
            original_principal: &admission.3,
            grant_digest,
            grant_active,
        },
    )?;
    Ok(UnknownSourceRows {
        taskrun_id,
        taskrun_attempt_id,
        conversation_id,
        principal_id: admission.3,
        provider_id: admission.15,
        provider_idempotency_key: admission.4,
        authority_id,
        authority_revision,
        runtime_authority_id,
        database_generation,
        runtime_generation,
        fencing_token,
        profile_digest,
        pricing_revision_digest,
        currency: admission.13,
        request_digest,
        token_reservation_id: ids.0,
        cost_reservation_id: ids.1,
        token_amount,
        cost_amount,
        reservations,
        original_effect,
        original,
        current,
    })
}
