use runne_runtime::provider_execution::{
    ProviderRemoteTerminalSourceCommit, ProviderRemoteTerminalSourceOutcome,
    ProviderRemoteTerminalSourcePersistence,
};

impl ProviderRemoteTerminalSourcePersistence for SqliteProviderExecutionStore {
    fn commit_remote_terminal_source(
        &self,
        request: &ProviderRemoteTerminalSourceCommit,
        authenticate: &dyn Fn(
            &runne_application::provider::ProviderRemoteAttemptRecord,
        ) -> Result<(), ProviderExecutionError>,
    ) -> Result<ProviderRemoteTerminalSourceOutcome, ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let snapshot = read_remote_attempt_in_transaction(&tx, request.attempt_id())?
            .ok_or(ProviderExecutionError::TerminalConflict)?;
        let verified =
            verify_remote_terminal_source_binding_tx(&tx, request, &snapshot, authenticate)?;
        let matching_identity: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM provider_remote_terminal_settlements
             WHERE dispatch_attempt_id=?1 AND taskrun_id=?2 AND taskrun_attempt_id=?3
               AND conversation_id=?4 AND begin_command_id=?5 AND generation_id=?6
               AND begin_event_digest=?7 AND terminal_status=?8 AND publication_disposition=?9
               AND request_digest=?10 AND response_id_digest=?11 AND artifact_digest=?12
               AND profile_digest=?13 AND pricing_revision_digest=?14
               AND runtime_authority_id=?15 AND database_generation=?16
               AND runtime_generation=?17 AND fencing_token=?18 AND expected_taskrun_version=?19
               AND published_output_digest IS ?20",
                rusqlite::params![
                    request.attempt_id().as_bytes().as_slice(),
                    request.taskrun_id().as_bytes().as_slice(),
                    request.taskrun_attempt_id().as_bytes().as_slice(),
                    verified.conversation_id.as_bytes().as_slice(),
                    verified.begin_command_id.as_bytes().as_slice(),
                    verified.generation_id.as_slice(),
                    verified.begin_event_digest.as_slice(),
                    request.terminal_status().code(),
                    publication_code(request.publication_disposition()),
                    request.request_digest().as_slice(),
                    request.response_id_digest().as_slice(),
                    request.artifact_digest().as_slice(),
                    request.profile_digest().as_slice(),
                    request.pricing_revision_digest().as_slice(),
                    request.runtime_authority_id().as_slice(),
                    i64::try_from(request.database_generation())
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    i64::try_from(request.runtime_generation())
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    i64::try_from(request.fencing_token())
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    i64::try_from(verified.expected_taskrun_version)
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    request.output_digest().map(|digest| digest.as_slice()),
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let existing_fact_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [request.attempt_id().as_bytes().as_slice()],
            |row| row.get(0),
        ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if existing_fact_count != matching_identity {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let expected_usage = request
            .usage()
            .map(|usage| {
                Ok::<_, std::num::TryFromIntError>((
                    i64::try_from(usage.input_tokens())?,
                    i64::try_from(usage.output_tokens())?,
                    i64::try_from(usage.cached_input_tokens())?,
                    i64::try_from(usage.reasoning_output_tokens())?,
                ))
            })
            .transpose()
            .map_err(|_| ProviderExecutionError::TerminalConflict)?;
        type PriorRemoteTerminalSettlement = Option<(
            i64,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )>;
        let prior: PriorRemoteTerminalSettlement = tx
            .query_row(
                "SELECT settlement_state,input_tokens,output_tokens,cached_input_tokens,
                    reasoning_output_tokens,charge_micros,currency,settlement_digest,
                    application_receipt_digest
             FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
                [request.attempt_id().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if let Some((
            state,
            input,
            output,
            cached,
            reasoning,
            charge,
            currency,
            digest,
            app_receipt,
        )) = prior
        {
            let expected_fields = expected_usage
                .map(|value| (Some(value.0), Some(value.1), Some(value.2), Some(value.3)));
            let actual_fields = (input, output, cached, reasoning);
            if state < 1 || actual_fields != expected_fields.unwrap_or((None, None, None, None)) {
                return Err(ProviderExecutionError::TerminalConflict);
            }
            if state == 3 || state == 5 {
                if charge.is_some() || currency.is_some() || digest.is_some() {
                    return Err(ProviderExecutionError::TerminalConflict);
                }
                persist_remote_terminal_audit_receipt(&tx, request, &verified)?;
                tx.commit()
                    .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
                return Ok(ProviderRemoteTerminalSourceOutcome::AuditOnly);
            }
            if state == 1 && charge.is_none() && currency.is_none() && digest.is_none() {
                let settled =
                    settle_remote_terminal(&tx, request, &snapshot, verified.publication_allowed)?;
                if settled.output_pending {
                    promote_remote_source_settlement(&tx, request)?;
                } else {
                    mark_remote_source_audit_only(&tx, request)?;
                    persist_remote_terminal_audit_receipt(&tx, request, &verified)?;
                }
                tx.commit()
                    .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
                return Ok(if source_delivery_allowed(request, &verified) {
                    ProviderRemoteTerminalSourceOutcome::CurrentGeneration
                } else {
                    ProviderRemoteTerminalSourceOutcome::AuditOnly
                });
            }
            if matches!(state, 2 | 4) {
                validate_accounted_remote_source(
                    &tx,
                    AccountedRemoteSourceFacts {
                        request,
                        state,
                        usage: (input, output, cached, reasoning),
                        financial: (charge, currency.as_deref(), digest.as_deref()),
                        application_receipt: app_receipt.as_deref(),
                        has_usage: expected_usage.is_some(),
                        outbox_required: request.publication_disposition()
                            == runne_provider::ProviderRemotePublicationDisposition::Allowed,
                    },
                )?;
                let stored_digest = digest
                    .as_deref()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
                if request
                    .charge_micros()
                    .is_some_and(|value| Some(value) != charge.and_then(|v| u64::try_from(v).ok()))
                    || request
                        .currency()
                        .is_some_and(|value| Some(value) != currency.as_deref())
                    || request
                        .settlement_digest()
                        .is_some_and(|value| Some(*value) != stored_digest)
                {
                    return Err(ProviderExecutionError::TerminalConflict);
                }
                tx.commit()
                    .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
                return Ok(if source_delivery_allowed(request, &verified) {
                    ProviderRemoteTerminalSourceOutcome::CurrentGeneration
                } else {
                    ProviderRemoteTerminalSourceOutcome::AuditOnly
                });
            }
            if charge.map(|value| value as u64) != request.charge_micros()
                || currency.as_deref() != request.currency()
                || digest
                    .as_deref()
                    .and_then(|value| value.try_into().ok())
                    != request.settlement_digest().copied()
            {
                return Err(ProviderExecutionError::TerminalConflict);
            }
        } else {
            let audit_only = !verified.current_generation_active
                || verified.current_taskrun_state.is_terminal()
                || verified.writer_owner_principal != verified.original_principal
                || !verified.publication_allowed;
            let output_candidate = request.terminal_status()
                == runne_application::provider::ProviderRemoteTerminalDisposition::Completed
                && request.publication_disposition()
                    == runne_provider::ProviderRemotePublicationDisposition::Allowed
                && request.output_digest().is_some()
                && verified.publication_allowed;
            let state = if output_candidate && !audit_only {
                1_i64
            } else {
                3_i64
            };
            tx.execute(
                "INSERT INTO provider_remote_terminal_settlements(
                    dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,
                    writer_owner_principal,writer_fencing_token,begin_command_id,generation_id,
                    begin_event_digest,source_kind,terminal_status,publication_disposition,
                    request_digest,response_id_digest,artifact_digest,published_output_digest,profile_digest,
                    pricing_revision_digest,runtime_authority_id,database_generation,
                    runtime_generation,fencing_token,expected_taskrun_version,settlement_state,
                    input_tokens,output_tokens,cached_input_tokens,reasoning_output_tokens,
                    charge_micros,currency,settlement_digest,created_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,2,?10,?11,?12,?13,?14,?15,?16,?17,
                        ?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,unixepoch())",
                rusqlite::params![
                    request.attempt_id().as_bytes().as_slice(),
                    request.taskrun_id().as_bytes().as_slice(),
                    request.taskrun_attempt_id().as_bytes().as_slice(),
                    verified.conversation_id.as_bytes().as_slice(),
                    verified.writer_owner_principal,
                    i64::try_from(verified.writer_fencing_token)
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    verified.begin_command_id.as_bytes().as_slice(),
                    verified.generation_id.as_slice(),
                    verified.begin_event_digest.as_slice(),
                    request.terminal_status().code(),
                    publication_code(request.publication_disposition()),
                    request.request_digest().as_slice(),
                    request.response_id_digest().as_slice(),
                    request.artifact_digest().as_slice(),
                    request.output_digest().map(|digest| digest.as_slice()),
                    request.profile_digest().as_slice(),
                    request.pricing_revision_digest().as_slice(),
                    request.runtime_authority_id().as_slice(),
                    i64::try_from(request.database_generation())
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    i64::try_from(request.runtime_generation())
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    i64::try_from(request.fencing_token())
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    i64::try_from(verified.expected_taskrun_version)
                        .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                    state,
                    expected_usage.map(|value| value.0),
                    expected_usage.map(|value| value.1),
                    expected_usage.map(|value| value.2),
                    expected_usage.map(|value| value.3),
                    None::<i64>,
                    None::<String>,
                    None::<&[u8]>,
                ],
            )
            .map_err(|_| ProviderExecutionError::TerminalConflict)?;
            let settled =
                settle_remote_terminal(&tx, request, &snapshot, verified.publication_allowed)?;
            if settled.output_pending {
                promote_remote_source_settlement(&tx, request)?;
            } else {
                mark_remote_source_audit_only(&tx, request)?;
                persist_remote_terminal_audit_receipt(&tx, request, &verified)?;
            }
        }
        tx.commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(if source_delivery_allowed(request, &verified) {
            ProviderRemoteTerminalSourceOutcome::CurrentGeneration
        } else {
            ProviderRemoteTerminalSourceOutcome::AuditOnly
        })
    }
}
