fn validate_request(request: &RouteNewWorkRequest) -> Result<(), MigrationRoutingError> {
    if request.request_digest.as_bytes() == &[0; 32]
        || request.feature_request.feature_profile != request.routing_unit.feature_profile
        || request.feature_request.contract_digest != request.routing_unit.contract_digest
        || request.feature_request.schema_digest != request.routing_unit.schema_digest
        || request.feature_request.config_digest != request.routing_unit.config_digest
    {
        return Err(MigrationRoutingError::RoutingUnitMismatch);
    }
    Ok(())
}

fn validate_candidate_claim(
    authority: &RuntimeAuthority,
    request: &RouteNewWorkRequest,
    registry: &VerifiedFeatureRegistry,
) -> Result<(), MigrationRoutingError> {
    let RuntimeAuthority::Candidate(generation) = authority else {
        return Ok(());
    };
    if request.feature_request.runtime_release != generation.as_str() {
        return Err(MigrationRoutingError::RoutingUnitMismatch);
    }
    registry
        .require_verified(&request.feature_request)
        .map(|_| ())
        .map_err(MigrationRoutingError::Feature)
}

fn validate_existing_intent(
    intent: &RoutingDispatchIntent,
    request: &RouteNewWorkRequest,
) -> Result<(), MigrationRoutingError> {
    if intent.aggregate_id != request.aggregate_id
        || intent.command_id != request.command_id
        || intent.idempotency_key != request.idempotency_key
        || intent.request_digest != request.request_digest
    {
        return Err(MigrationRoutingError::Store(
            MigrationStoreError::DispatchIntentConflict,
        ));
    }
    Ok(())
}

fn terminal_decision(
    binding: RuntimeBinding,
    status: DispatchIntentStatus,
) -> Result<RouteDecision, MigrationRoutingError> {
    match status {
        DispatchIntentStatus::Accepted => Ok(RouteDecision {
            binding,
            dispatch_status: status,
        }),
        DispatchIntentStatus::RejectedBeforeAcceptance => {
            Err(MigrationRoutingError::RejectedBeforeAcceptance)
        }
        DispatchIntentStatus::Pending | DispatchIntentStatus::Indeterminate => {
            Err(MigrationRoutingError::ReconciliationRequired)
        }
    }
}
