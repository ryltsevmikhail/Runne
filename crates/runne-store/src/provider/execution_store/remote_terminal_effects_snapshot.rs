pub(crate) fn load_remote_effects_snapshot_in_transaction(
    transaction: &Transaction<'_>,
    runtime_authority_id: &runne_application::ports::RuntimeAuthorityId,
    taskrun_id: TaskRunId,
    taskrun_attempt_id: AttemptId,
    authenticator: Option<&dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
    successor_eligibility: runne_api::SuccessorEligibilityV1,
) -> Result<
    Option<runne_application::provider::ProviderRemoteEffectsSnapshot>,
    ProviderExecutionError,
> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let now = i64::try_from(now.as_secs()).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    load_remote_effects_snapshot_at(
        transaction,
        runtime_authority_id,
        taskrun_id,
        taskrun_attempt_id,
        authenticator,
        successor_eligibility,
        now,
    )
}

fn load_remote_effects_snapshot_at(
    transaction: &Transaction<'_>,
    runtime_authority_id: &runne_application::ports::RuntimeAuthorityId,
    taskrun_id: TaskRunId,
    taskrun_attempt_id: AttemptId,
    authenticator: Option<&dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
    successor_eligibility: runne_api::SuccessorEligibilityV1,
    now: i64,
) -> Result<
    Option<runne_application::provider::ProviderRemoteEffectsSnapshot>,
    ProviderExecutionError,
> {
    use runne_application::provider::{
        ProviderRemoteEffectsSnapshot, ProviderRemoteObservationProjection as Observation,
    };

    let ids = crate::store::test_support_diagnostics::on_error(
        "remote.dispatch_lookup",
        remote_effect_dispatch_ids(transaction, taskrun_id, taskrun_attempt_id),
    )?;
    let [dispatch] = ids.as_slice() else {
        if ids.is_empty() {
            return Ok(None);
        }
        crate::store::test_support_diagnostics::record("remote.dispatch_ambiguous");
        return Err(ProviderExecutionError::JournalCorrupt);
    };
    let dispatch = DispatchAttemptId::from_bytes(*dispatch);
    let record = crate::store::test_support_diagnostics::on_error(
        "remote.attempt_read",
        read_remote_attempt_in_transaction(transaction, dispatch),
    )?
    .ok_or_else(|| {
        crate::store::test_support_diagnostics::record("remote.attempt_missing");
        ProviderExecutionError::JournalCorrupt
    })?;
    let binding = &record.request.binding;
    if binding.taskrun_id != taskrun_id
        || binding.taskrun_attempt_id != taskrun_attempt_id
        || binding.dispatch_attempt_id != dispatch
        || crate::schema::read_authority_id(transaction)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            != Some(binding.runtime_authority_id)
        || crate::schema::read_event_log_lineage_id(transaction)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .is_none()
    {
        crate::store::test_support_diagnostics::record("remote.attempt_binding");
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    crate::store::test_support_diagnostics::on_error(
        "remote.response_binding",
        validate_historical_response_binding(transaction, binding, record.request.key, i64::MAX),
    )?;
    crate::store::test_support_diagnostics::on_error(
        "remote.submit_origin",
        crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
            transaction,
            dispatch.as_bytes(),
            runtime_authority_id,
        )
        .map_err(|_| ProviderExecutionError::JournalCorrupt),
    )?;

    let fact = match (&record.terminal, authenticator) {
        (None, _) => None,
        (Some(_), Some(authenticator)) => {
            let expected = crate::store::test_support_diagnostics::on_error(
                "remote.expected_identity",
                remote_expected_identity(binding),
            )?;
            crate::store::test_support_diagnostics::on_error(
                "remote.fact_authentication",
                authenticator
                    .authenticate_terminal_snapshot(&record, &expected)
                    .map_err(|_| ProviderExecutionError::JournalCorrupt),
            )?
        }
        (Some(_), None) => None,
    };
    let observation = if record.terminal.is_none() {
        let observation =
            crate::provider::read_remote_observation_in_transaction(transaction, binding, now)?;
        if observation.status == runne_provider::ProviderRemoteResponseStatus::Pending
            && matches!(
                observation.state,
                ProviderRemoteObservationState::Pending
                    | ProviderRemoteObservationState::Outstanding
            )
        {
            Observation::Pending
        } else if observation.state == ProviderRemoteObservationState::None {
            Observation::NotObserved
        } else {
            Observation::Unknown
        }
    } else {
        Observation::NotObserved
    };
    let local_disposition = crate::store::test_support_diagnostics::on_error(
        "remote.local_disposition",
        remote_local_disposition(transaction, &record, fact.as_ref()),
    )?;
    let accounting = crate::store::test_support_diagnostics::on_error(
        "remote.accounting_projection",
        remote_accounting_projection(transaction, &record, fact.as_ref(), authenticator),
    )?;
    let secondary_grant = crate::store::test_support_diagnostics::on_error(
        "remote.grant_projection",
        remote_grant_projection(transaction, binding),
    )?;
    let credential = crate::store::test_support_diagnostics::on_error(
        "remote.credential_projection",
        remote_credential_projection(transaction, binding),
    )?;
    Ok(Some(ProviderRemoteEffectsSnapshot {
        binding: binding.clone(),
        fact,
        observation,
        local_disposition,
        accounting,
        secondary_grant,
        credential,
        successor_eligibility,
    }))
}

fn remote_effect_dispatch_ids(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
    taskrun_attempt_id: AttemptId,
) -> Result<Vec<[u8; 16]>, ProviderExecutionError> {
    let mut statement = transaction
        .prepare(
            "SELECT dispatch_attempt_id FROM provider_remote_request_intents
             WHERE taskrun_id=?1 AND taskrun_attempt_id=?2
             ORDER BY dispatch_attempt_id LIMIT 2",
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let rows = statement
        .query_map(
            params![
                taskrun_id.as_bytes().as_slice(),
                taskrun_attempt_id.as_bytes().as_slice()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    rows.map(|row| {
        row.map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .as_slice()
            .try_into()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)
    })
    .collect()
}

fn remote_expected_identity(
    binding: &runne_application::provider::ProviderRemoteAttemptBinding,
) -> Result<runne_provider::ProviderRecoveryAttemptIdentity, ProviderExecutionError> {
    let provider = runne_provider::ProviderId::new(binding.provider_id.clone())
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let realm = runne_provider::ProviderId::new(binding.credential_realm.clone())
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    runne_provider::ProviderRecoveryAttemptIdentity::new(
        provider,
        realm,
        binding.profile_id.clone(),
        binding.profile_digest,
        binding.semantic_digest,
        binding.prepared_digest,
        binding.pricing_digest,
        binding.request_digest,
        binding.runtime_authority_id,
        binding.database_generation,
        binding.runtime_generation,
        binding.fencing_token,
    )
    .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

include!("remote_terminal_effects_snapshot_state.rs");
include!("remote_terminal_effects_snapshot_finance.rs");
