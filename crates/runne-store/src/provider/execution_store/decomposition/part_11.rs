#[allow(clippy::too_many_arguments)]
fn commit_issuance(
    transaction: &Transaction<'_>,
    issuance_guard: &crate::schema::OnlineIssuanceGuard,
    online_proof: &OnlineEffectProofCapabilitySet,
    request: &ProviderAuthorityIssueRequest,
    state: &RuntimeAuthorityState,
    claim: &ProviderDispatchClaim,
    authority_ref: ProviderEffectAuthorityRef,
    semantic_digest: [u8; 32],
    requested_tokens: u64,
    profile_grant: Option<([u8; 16], [u8; 16])>,
    issued_at: i64,
    expires_at: i64,
) -> Result<(), ProviderAdmissionError> {
    let requested_tokens_i64 = as_i64(requested_tokens)?;
    let requested_input_i64 = as_i64(request.requested_input_tokens)?;
    let requested_output_i64 = as_i64(request.requested_output_tokens)?;
    let max_cost_i64 = as_i64(request.max_cost_micros)?;
    let generation_i64 = as_i64(state.expected_generation)?;
    let fence_i64 = as_i64(state.expected_fencing_token)?;
    let database_generation_i64 = as_i64(state.database_generation)?;
    let authority_revision_i64 = as_i64(authority_ref.revision())?;
    let _issuance_scope = issuance_guard
        .enable(
            *claim.attempt_id.as_bytes(),
            request.provider_id.as_str(),
            authority_ref.authority_id(),
            authority_revision_i64,
            issued_at,
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    let intent_id = format!("provider:{}", encode_hex(claim.attempt_id.as_bytes()));
    let budget_binding = format!(
        "provider:{}:{}",
        encode_hex(&claim.token_reservation_id),
        encode_hex(&claim.cost_reservation_id)
    );
    let permit_hex = encode_hex(&claim.permit_id);
    let reserved = match profile_grant {
        Some((grant_id, binding_id)) => transaction.execute(
            "UPDATE provider_secondary_profile_grants SET
                token_budget_reserved=token_budget_reserved+?1,
                cost_budget_reserved_micros=cost_budget_reserved_micros+?2
             WHERE grant_id=?3 AND enabled=1
               AND runtime_authority_id=?4 AND database_generation=?5
               AND EXISTS(SELECT 1 FROM provider_secondary_profile_bindings b WHERE b.binding_id=?6
                   AND b.grant_id=?3 AND b.closed_at IS NULL AND b.owner_id=?7
                   AND b.authority_revision=?8 AND b.scope=?9
                   AND b.activation_binding_kind=?10 AND b.activation_binding_digest=?11)
               AND profile_digest=?12 AND pricing_revision_digest=?13
               AND token_budget_reserved+token_budget_settled+?1<=token_budget_limit
               AND cost_budget_reserved_micros+cost_budget_settled_micros+?2<=cost_budget_limit_micros",
            params![requested_tokens_i64,max_cost_i64,grant_id.as_slice(),state.runtime_authority_id.as_slice(),
                database_generation_i64,binding_id.as_slice(),state.owner_id,as_i64(state.state_revision)?,state.scope,
                state.activation_binding_kind.ok_or(ProviderAdmissionError::AuthorityDenied)?.code(),
                state.activation_binding_digest.as_slice(),request.prepared.profile_digest.as_slice(),request.pricing_revision_digest.as_slice()],
        ),
        None => transaction.execute(
            "UPDATE provider_runtime_authority_state SET
                token_budget_reserved = token_budget_reserved + ?1,
                cost_budget_reserved_micros = cost_budget_reserved_micros + ?2
             WHERE id = 1 AND active = 1
               AND expected_generation = lease_generation
               AND expected_fencing_token = lease_fencing_token
               AND token_budget_reserved + token_budget_settled + ?1 <= token_budget_limit
               AND cost_budget_reserved_micros + cost_budget_settled_micros + ?2
                   <= cost_budget_limit_micros",
            params![requested_tokens_i64, max_cost_i64],
        ),
    }
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if reserved != 1 {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }

    transaction
        .execute(
            "INSERT INTO provider_dispatch_attempts (
                attempt_id, call_id, permit_id, token_reservation_id, cost_reservation_id,
                fencing_token, provider_idempotency_key, prepared_digest, render_digest,
                profile_digest, state, stream_id, settlement_digest, pre_effect_rejection
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, NULL, NULL, NULL)",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.call_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                fence_i64,
                claim.provider_idempotency_key,
                claim.prepared_digest.as_slice(),
                claim.render_digest.as_slice(),
                claim.profile_digest.as_slice(),
            ],
        )
        .map_err(|_| ProviderAdmissionError::AuthorityConflict)?;
    transaction
        .execute(
            "INSERT INTO provider_effect_authorities (
                authority_id, revision, attempt_id, permit_id, capability_grant_id,
                token_reservation_id, cost_reservation_id, prepared_digest, render_digest,
                profile_digest, owner_id, scope, fencing_token, expires_at, revoked, consumed,
                consumed_intent_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                       0, 1, ?15)",
            params![
                authority_ref.authority_id().as_slice(),
                authority_revision_i64,
                claim.attempt_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                state.capability_grant_id,
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                claim.prepared_digest.as_slice(),
                claim.render_digest.as_slice(),
                claim.profile_digest.as_slice(),
                state.owner_id,
                state.scope,
                fence_i64,
                expires_at,
                intent_id,
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    transaction
        .execute(
            "INSERT INTO provider_execution_admissions (
                provider_idempotency_key, semantic_digest, principal_id, conversation_id,
                taskrun_id, execution_attempt_id, call_id, dispatch_attempt_id, authority_id,
                authority_revision, permit_id, token_reservation_id, cost_reservation_id,
                runtime_authority_id, database_generation, generation, fencing_token,
                prepared_digest, render_digest, profile_digest, pricing_revision_digest,
                requested_input_tokens, requested_output_tokens, max_cost_micros, currency,
                issued_at, expires_at, owner_id, scope, capability_grant_id,
                capability_revision, capability_expires_at, capability_revocation_epoch,
                capability_revocation_observed,
                approval_id, approval_revision, approval_expires_at, approval_revocation_epoch,
                approval_revocation_observed,
                activation_binding_kind, activation_binding_digest
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28,
                ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39
                , ?40, ?41
             )",
            params![
                request.provider_idempotency_key,
                semantic_digest.as_slice(),
                request.principal_id,
                request.conversation_id.as_bytes().as_slice(),
                request.taskrun_id.as_bytes().as_slice(),
                request.execution_attempt_id.as_bytes().as_slice(),
                request.prepared.call_id.as_bytes().as_slice(),
                claim.attempt_id.as_bytes().as_slice(),
                authority_ref.authority_id().as_slice(),
                authority_revision_i64,
                claim.permit_id.as_slice(),
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                state.runtime_authority_id.as_slice(),
                database_generation_i64,
                generation_i64,
                fence_i64,
                request.prepared.prepared_digest.as_slice(),
                request.prepared.render_digest.as_slice(),
                request.prepared.profile_digest.as_slice(),
                request.pricing_revision_digest.as_slice(),
                requested_input_i64,
                requested_output_i64,
                max_cost_i64,
                request.currency,
                issued_at,
                expires_at,
                state.owner_id,
                state.scope,
                state.capability_grant_id,
                as_i64(state.capability_revision)?,
                state.capability_expires_at,
                as_i64(state.capability_revocation_epoch)?,
                i64::from(state.capability_revocation_observed),
                state.approval_id,
                as_i64(state.approval_revision)?,
                state.approval_expires_at,
                as_i64(state.approval_revocation_epoch)?,
                i64::from(state.approval_revocation_observed),
                state
                    .activation_binding_kind
                    .ok_or(ProviderAdmissionError::AuthorityDenied)?
                    .code(),
                state.activation_binding_digest.as_slice(),
            ],
        )
        .map_err(|_| ProviderAdmissionError::AuthorityConflict)?;
    if let Some((grant_id, binding_id)) = profile_grant {
        transaction.execute(
            "INSERT INTO provider_secondary_profile_attempts
             (dispatch_attempt_id,grant_id,binding_id,provider_idempotency_key,profile_digest,pricing_revision_digest)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![claim.attempt_id.as_bytes().as_slice(),grant_id.as_slice(),binding_id.as_slice(),request.provider_idempotency_key,
                request.prepared.profile_digest.as_slice(),request.pricing_revision_digest.as_slice()],
        ).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    }
    persist_online_issuance_binding(transaction, request, claim, online_proof)?;
    for (reservation_id, dimension, amount) in [
        (claim.token_reservation_id, 1_i64, requested_tokens_i64),
        (claim.cost_reservation_id, 2_i64, max_cost_i64),
    ] {
        transaction
            .execute(
                "INSERT INTO provider_budget_reservations (
                    reservation_id, provider_idempotency_key, dimension, amount, state,
                    settled_amount, released_at
                 ) VALUES (?1, ?2, ?3, ?4, 1, NULL, NULL)",
                params![
                    reservation_id.as_slice(),
                    request.provider_idempotency_key,
                    dimension,
                    amount,
                ],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    }
    persist_issuance_security_records(
        transaction,
        &intent_id,
        &budget_binding,
        &permit_hex,
        &state.capability_grant_id,
        requested_tokens_i64,
    )?;
    Ok(())
}

struct IssuedIds {
    dispatch_attempt_id: [u8; 16],
    authority_id: [u8; 16],
    permit_id: [u8; 16],
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
}

impl IssuedIds {
    fn random_with_dispatch_attempt_id(dispatch_attempt_id: Option<[u8; 16]>) -> Self {
        Self {
            dispatch_attempt_id: dispatch_attempt_id.unwrap_or_else(random_nonzero_id),
            authority_id: random_nonzero_id(),
            permit_id: random_nonzero_id(),
            token_reservation_id: random_nonzero_id(),
            cost_reservation_id: random_nonzero_id(),
        }
    }
}

fn random_nonzero_id() -> [u8; 16] {
    loop {
        let mut id = [0_u8; 16];
        OsRng.fill_bytes(&mut id);
        if id != [0; 16] {
            return id;
        }
    }
}

fn as_i64(value: u64) -> Result<i64, ProviderAdmissionError> {
    i64::try_from(value).map_err(|_| ProviderAdmissionError::InvalidSemanticContext)
}
