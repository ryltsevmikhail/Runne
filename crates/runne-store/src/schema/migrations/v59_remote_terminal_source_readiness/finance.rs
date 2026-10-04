use super::*;

pub(super) fn matches(
    connection: &Connection,
    row: &SourceReadinessRow,
    original_principal: &str,
) -> SqliteResult<bool> {
    let valid: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM provider_remote_terminal_settlements s
           JOIN provider_execution_admissions admission USING(dispatch_attempt_id)
           JOIN provider_dispatch_attempts d ON d.attempt_id=s.dispatch_attempt_id
           JOIN provider_prepared_requests prepared ON prepared.call_id=admission.call_id
           JOIN provider_effect_authorities effect_authority
             ON effect_authority.authority_id=admission.authority_id
            AND effect_authority.revision=admission.authority_revision
           JOIN provider_effect_starts effect ON effect.dispatch_attempt_id=s.dispatch_attempt_id
           JOIN provider_online_dispatch_claim_providers claim_provider
             ON claim_provider.dispatch_attempt_id=s.dispatch_attempt_id
           JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
           JOIN provider_online_credential_effect_bindings credential
             ON credential.dispatch_attempt_id=s.dispatch_attempt_id
           JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
           JOIN provider_remote_terminal_artifacts artifact USING(dispatch_attempt_id)
           JOIN provider_accounting_settlements f USING(dispatch_attempt_id)
           JOIN provider_terminal_dispositions disposition USING(dispatch_attempt_id)
           WHERE s.dispatch_attempt_id=?1 AND admission.principal_id=?2
             AND effect_authority.attempt_id=s.dispatch_attempt_id
             AND effect_authority.permit_id=admission.permit_id
             AND effect_authority.token_reservation_id=admission.token_reservation_id
             AND effect_authority.cost_reservation_id=admission.cost_reservation_id
             AND effect_authority.prepared_digest=admission.prepared_digest
             AND effect_authority.render_digest=admission.render_digest
             AND effect_authority.profile_digest=admission.profile_digest
             AND effect_authority.fencing_token=admission.fencing_token
             AND s.taskrun_id=admission.taskrun_id
             AND s.taskrun_attempt_id=admission.execution_attempt_id
             AND s.conversation_id=admission.conversation_id
             AND s.runtime_authority_id=admission.runtime_authority_id
             AND s.database_generation=admission.database_generation
             AND s.runtime_generation=admission.generation
             AND s.fencing_token=admission.fencing_token
             AND s.profile_digest=admission.profile_digest
             AND s.pricing_revision_digest=admission.pricing_revision_digest
             AND admission.currency=f.currency
             AND d.provider_idempotency_key=admission.provider_idempotency_key
             AND d.call_id=admission.call_id AND d.permit_id=admission.permit_id
             AND d.token_reservation_id=admission.token_reservation_id
             AND d.cost_reservation_id=admission.cost_reservation_id
             AND d.prepared_digest=admission.prepared_digest
             AND d.render_digest=admission.render_digest
             AND d.profile_digest=admission.profile_digest
             AND effect.provider_idempotency_key=admission.provider_idempotency_key
             AND effect.permit_id=admission.permit_id
             AND prepared.prepared_digest=admission.prepared_digest
             AND prepared.render_digest=admission.render_digest
             AND prepared.profile_digest=admission.profile_digest
             AND q.taskrun_id=s.taskrun_id AND q.taskrun_attempt_id=s.taskrun_attempt_id
             AND q.runtime_authority_id=s.runtime_authority_id
             AND q.database_generation=s.database_generation
             AND q.runtime_generation=s.runtime_generation AND q.fencing_token=s.fencing_token
             AND q.profile_digest=s.profile_digest
             AND q.pricing_revision_digest=s.pricing_revision_digest
             AND q.semantic_digest=admission.semantic_digest
             AND q.prepared_digest=admission.prepared_digest
             AND q.request_digest=admission.render_digest
             AND q.plaintext_digest=q.request_digest
             AND q.provider_id=claim_provider.provider_id
             AND q.credential_realm=credential.provider_id
             AND r.taskrun_id=q.taskrun_id AND r.taskrun_attempt_id=q.taskrun_attempt_id
             AND r.provider_id=q.provider_id AND r.profile_id=q.profile_id
             AND r.profile_digest=q.profile_digest
             AND r.pricing_revision_digest=q.pricing_revision_digest
             AND r.credential_realm=q.credential_realm
             AND r.request_digest=q.request_digest
             AND r.key_id=q.key_id AND r.key_version=q.key_version
             AND r.runtime_authority_id=q.runtime_authority_id
             AND r.database_generation=q.database_generation
             AND r.runtime_generation=q.runtime_generation AND r.fencing_token=q.fencing_token
             AND artifact.taskrun_id=q.taskrun_id
             AND artifact.taskrun_attempt_id=q.taskrun_attempt_id
             AND artifact.provider_id=q.provider_id AND artifact.profile_id=q.profile_id
             AND artifact.profile_digest=q.profile_digest
             AND artifact.pricing_revision_digest=q.pricing_revision_digest
             AND artifact.semantic_digest=q.semantic_digest
             AND artifact.prepared_digest=q.prepared_digest
             AND artifact.credential_realm=q.credential_realm
             AND artifact.request_digest=q.request_digest
             AND artifact.key_id=r.key_id AND artifact.key_version=r.key_version
             AND artifact.response_id_digest=r.plaintext_digest
             AND artifact.runtime_authority_id=q.runtime_authority_id
             AND artifact.database_generation=q.database_generation
             AND artifact.runtime_generation=q.runtime_generation
             AND artifact.fencing_token=q.fencing_token
             AND artifact.disposition=s.terminal_status
             AND artifact.plaintext_digest=s.artifact_digest
             AND f.pricing_revision_digest=s.pricing_revision_digest
             AND f.input_tokens=s.input_tokens AND f.output_tokens=s.output_tokens
             AND f.cached_input_tokens=s.cached_input_tokens
             AND f.reasoning_output_tokens=s.reasoning_output_tokens
             AND f.charge_micros=s.charge_micros AND f.currency=s.currency
             AND f.settlement_digest=s.settlement_digest
             AND disposition.disposition=1
             AND (SELECT COUNT(*) FROM provider_budget_reservations b
                  WHERE b.provider_idempotency_key=admission.provider_idempotency_key)=2
             AND EXISTS(SELECT 1 FROM provider_budget_reservations token
                  WHERE token.reservation_id=admission.token_reservation_id
                    AND token.provider_idempotency_key=admission.provider_idempotency_key
                    AND token.dimension=1
                    AND token.amount=admission.requested_input_tokens+admission.requested_output_tokens
                    AND token.state=2 AND token.released_at IS NOT NULL
                    AND token.settled_amount<=token.amount
                    AND token.settled_amount=f.input_tokens+f.output_tokens)
             AND EXISTS(SELECT 1 FROM provider_budget_reservations cost
                  WHERE cost.reservation_id=admission.cost_reservation_id
                    AND cost.provider_idempotency_key=admission.provider_idempotency_key
                    AND cost.dimension=2 AND cost.amount=admission.max_cost_micros
                    AND cost.state=2 AND cost.released_at IS NOT NULL
                    AND cost.settled_amount<=cost.amount
                    AND cost.settled_amount=f.charge_micros)
         )",
        rusqlite::params![row.dispatch.as_slice(), original_principal],
        |saved| saved.get(0),
    )?;
    Ok(valid)
}
