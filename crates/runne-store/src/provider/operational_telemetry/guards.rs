use runne_application::provider::{
    ProviderOperationalTelemetryScope, ProviderOperationalTelemetrySourceError,
};
use rusqlite::Transaction;

use super::TelemetryResult;
use super::aggregates::candidate_bindings;

pub(super) fn authority(
    transaction: &Transaction<'_>,
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<()> {
    authority_rows(transaction)?;
    authority_dispatch(transaction, scope)
}

fn authority_rows(transaction: &Transaction<'_>) -> TelemetryResult<()> {
    invalid(
        transaction,
        "SELECT EXISTS(
        SELECT 1 FROM provider_runtime_authority_state runtime
        WHERE runtime.id = 1 AND (runtime.capability_allowed NOT IN (0, 1)
          OR runtime.approval_allowed NOT IN (0, 1)
          OR runtime.capability_revocation_observed NOT IN (0, 1)
          OR runtime.approval_revocation_observed NOT IN (0, 1))
        UNION ALL
        SELECT 1 FROM provider_effect_authorities authority
        WHERE authority.revoked NOT IN (0, 1) OR authority.consumed NOT IN (0, 1)
          OR (authority.consumed = 0 AND authority.consumed_intent_id IS NOT NULL)
          OR (authority.consumed = 1 AND authority.consumed_intent_id IS NULL)
          OR (authority.consumed = 1 AND authority.consumed_intent_id
              <> ('provider:' || lower(hex(authority.attempt_id))))
          OR NOT EXISTS (
            SELECT 1 FROM provider_execution_admissions admission
            WHERE admission.authority_id = authority.authority_id
              AND admission.authority_revision = authority.revision
              AND authority.attempt_id = admission.dispatch_attempt_id
              AND authority.permit_id = admission.permit_id
              AND authority.capability_grant_id = admission.capability_grant_id
              AND authority.token_reservation_id = admission.token_reservation_id
              AND authority.cost_reservation_id = admission.cost_reservation_id
              AND authority.prepared_digest = admission.prepared_digest
              AND authority.render_digest = admission.render_digest
              AND authority.profile_digest = admission.profile_digest
              AND authority.owner_id = admission.owner_id
              AND authority.scope = admission.scope
              AND authority.fencing_token = admission.fencing_token
              AND authority.expires_at = admission.expires_at
          )
    )",
    )
}

fn authority_dispatch(
    transaction: &Transaction<'_>,
    scope: &ProviderOperationalTelemetryScope,
) -> TelemetryResult<()> {
    let invalid: i64 = transaction.query_row(
        "WITH runtime AS (
             SELECT * FROM provider_runtime_authority_state runtime
             WHERE runtime.id = 1 AND runtime.active = 1
               AND runtime.runtime_authority_id = :runtime_authority_id
               AND runtime.database_generation = :database_generation
               AND runtime.expected_generation = :launch_generation
               AND runtime.lease_generation = :launch_generation
               AND runtime.expected_fencing_token = :fencing_token
               AND runtime.lease_fencing_token = :fencing_token
               AND runtime.profile_digest = :profile_digest
         ), envelope AS (
             SELECT admission.dispatch_attempt_id, admission.call_id, admission.permit_id,
                    admission.token_reservation_id, admission.cost_reservation_id,
                    admission.fencing_token, admission.provider_idempotency_key,
                    admission.prepared_digest, admission.render_digest, admission.profile_digest
             FROM provider_effect_authorities authority
             JOIN provider_execution_admissions admission
               ON admission.authority_id = authority.authority_id
              AND admission.authority_revision = authority.revision
              AND authority.attempt_id = admission.dispatch_attempt_id
              AND authority.permit_id = admission.permit_id
              AND authority.capability_grant_id = admission.capability_grant_id
              AND authority.token_reservation_id = admission.token_reservation_id
              AND authority.cost_reservation_id = admission.cost_reservation_id
              AND authority.prepared_digest = admission.prepared_digest
              AND authority.render_digest = admission.render_digest
              AND authority.profile_digest = admission.profile_digest
              AND authority.owner_id = admission.owner_id
              AND authority.scope = admission.scope
              AND authority.fencing_token = admission.fencing_token
              AND authority.expires_at = admission.expires_at
             JOIN runtime ON admission.runtime_authority_id = runtime.runtime_authority_id
              AND admission.database_generation = runtime.database_generation
              AND admission.profile_digest = runtime.profile_digest
              AND admission.generation = runtime.expected_generation
              AND admission.fencing_token = runtime.expected_fencing_token
              AND admission.principal_id = runtime.principal_id
              AND admission.owner_id = runtime.owner_id
              AND admission.scope = runtime.scope
              AND admission.capability_grant_id = runtime.capability_grant_id
              AND admission.capability_revision = runtime.capability_revision
              AND admission.capability_expires_at = runtime.capability_expires_at
              AND admission.capability_revocation_epoch = runtime.capability_revocation_epoch
              AND admission.capability_revocation_observed = runtime.capability_revocation_observed
              AND admission.approval_id = runtime.approval_id
              AND admission.approval_revision = runtime.approval_revision
              AND admission.approval_expires_at = runtime.approval_expires_at
              AND admission.approval_revocation_epoch = runtime.approval_revocation_epoch
              AND admission.approval_revocation_observed = runtime.approval_revocation_observed
              AND admission.pricing_revision_digest = runtime.pricing_revision_digest
              AND admission.activation_binding_kind = runtime.activation_binding_kind
              AND admission.activation_binding_digest = runtime.activation_binding_digest
             WHERE authority.revoked = 0 AND authority.consumed = 1
               AND authority.consumed_intent_id = ('provider:' || lower(hex(admission.dispatch_attempt_id)))
               AND runtime.capability_allowed = 1 AND runtime.approval_allowed = 1
               AND runtime.capability_revocation_observed = 0
               AND runtime.approval_revocation_observed = 0
               AND NOT EXISTS (
                   SELECT 1 FROM provider_effect_starts effect
                   WHERE effect.dispatch_attempt_id = admission.dispatch_attempt_id
               )
         )
         SELECT EXISTS(
             SELECT 1 FROM envelope
             LEFT JOIN provider_dispatch_attempts dispatch
               ON dispatch.attempt_id = envelope.dispatch_attempt_id
             WHERE dispatch.attempt_id IS NULL
                OR dispatch.state NOT IN (1, 2, 3, 4, 5, 6)
                OR (dispatch.state = 1 AND (
                    dispatch.call_id <> envelope.call_id
                 OR dispatch.permit_id <> envelope.permit_id
                 OR dispatch.token_reservation_id <> envelope.token_reservation_id
                 OR dispatch.cost_reservation_id <> envelope.cost_reservation_id
                 OR dispatch.fencing_token <> envelope.fencing_token
                 OR dispatch.provider_idempotency_key <> envelope.provider_idempotency_key
                 OR dispatch.prepared_digest <> envelope.prepared_digest
                 OR dispatch.render_digest <> envelope.render_digest
                 OR dispatch.profile_digest <> envelope.profile_digest
             ))
         )",
        rusqlite::params_from_iter(candidate_bindings(scope)?),
        |row| row.get(0),
    ).map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?;
    (invalid == 0)
        .then_some(())
        .ok_or(ProviderOperationalTelemetrySourceError::Unavailable)
}

pub(super) fn approval(transaction: &Transaction<'_>) -> TelemetryResult<()> {
    invalid(
        transaction,
        "SELECT EXISTS(
        SELECT 1 FROM provider_runtime_authority_state runtime
        WHERE runtime.id = 1 AND (runtime.approval_allowed NOT IN (0, 1)
          OR runtime.approval_revocation_observed NOT IN (0, 1))
    )",
    )
}

pub(super) fn effects(transaction: &Transaction<'_>) -> TelemetryResult<()> {
    dispatches(transaction)?;
    invalid(
        transaction,
        "SELECT EXISTS(
        SELECT 1 FROM provider_effect_starts effect
        WHERE effect.state <> 1 OR effect.effect_expires_at <> effect.effect_started_at + 120
          OR NOT EXISTS (
            SELECT 1 FROM provider_execution_admissions admission
            JOIN provider_dispatch_attempts dispatch
              ON dispatch.attempt_id = admission.dispatch_attempt_id
             AND dispatch.call_id = admission.call_id
             AND dispatch.permit_id = admission.permit_id
             AND dispatch.token_reservation_id = admission.token_reservation_id
             AND dispatch.cost_reservation_id = admission.cost_reservation_id
             AND dispatch.fencing_token = admission.fencing_token
             AND dispatch.provider_idempotency_key = admission.provider_idempotency_key
             AND dispatch.prepared_digest = admission.prepared_digest
             AND dispatch.render_digest = admission.render_digest
             AND dispatch.profile_digest = admission.profile_digest
            WHERE effect.dispatch_attempt_id = admission.dispatch_attempt_id
              AND effect.provider_idempotency_key = admission.provider_idempotency_key
              AND effect.dispatch_attempt_id = dispatch.attempt_id
              AND effect.provider_idempotency_key = dispatch.provider_idempotency_key
              AND effect.permit_id = dispatch.permit_id
          )
    )",
    )
}

pub(super) fn uncertain(transaction: &Transaction<'_>) -> TelemetryResult<()> {
    dispatches(transaction)
}

fn dispatches(transaction: &Transaction<'_>) -> TelemetryResult<()> {
    invalid(
        transaction,
        "SELECT EXISTS(
        SELECT 1 FROM provider_dispatch_attempts dispatch
        WHERE dispatch.state NOT IN (1, 2, 3, 4, 5, 6) OR NOT EXISTS (
          SELECT 1 FROM provider_execution_admissions admission
          WHERE dispatch.attempt_id = admission.dispatch_attempt_id
            AND dispatch.call_id = admission.call_id
            AND dispatch.permit_id = admission.permit_id
            AND dispatch.token_reservation_id = admission.token_reservation_id
            AND dispatch.cost_reservation_id = admission.cost_reservation_id
            AND dispatch.fencing_token = admission.fencing_token
            AND dispatch.provider_idempotency_key = admission.provider_idempotency_key
            AND dispatch.prepared_digest = admission.prepared_digest
            AND dispatch.render_digest = admission.render_digest
            AND dispatch.profile_digest = admission.profile_digest
        )
    )",
    )
}

fn invalid(transaction: &Transaction<'_>, sql: &str) -> TelemetryResult<()> {
    let invalid: i64 = transaction
        .query_row(sql, [], |row| row.get(0))
        .map_err(|_| ProviderOperationalTelemetrySourceError::Unavailable)?;
    (invalid == 0)
        .then_some(())
        .ok_or(ProviderOperationalTelemetrySourceError::Unavailable)
}
