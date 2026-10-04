/// Called under the publication write transaction so Revoke cannot interleave.
pub(super) fn verify_online_publication(
    connection: &Connection,
    attempt: DispatchAttemptId,
    now: Option<i64>,
) -> Result<(), ProviderStoreError> {
    let current: bool = connection
        .query_row(
            "SELECT (NOT EXISTS (
                SELECT 1 FROM provider_online_dispatch_claim_providers
                WHERE dispatch_attempt_id=?1
             ) OR EXISTS (
                SELECT 1 FROM provider_online_credential_effect_bindings binding
                JOIN provider_online_dispatch_claim_providers claim
                  ON claim.dispatch_attempt_id=binding.dispatch_attempt_id
                 AND claim.provider_id=binding.provider_id
                JOIN provider_credential_authority_heads head
                  ON head.provider_id=binding.provider_id
                JOIN provider_execution_admissions admission
                  ON admission.dispatch_attempt_id=binding.dispatch_attempt_id
                JOIN provider_effect_starts effect
                  ON effect.dispatch_attempt_id=binding.dispatch_attempt_id
                JOIN provider_credential_versions mirror
                  ON mirror.provider_id=head.provider_id
                 AND mirror.credential_version=head.active_credential_version
                 AND mirror.ref_digest=head.active_ref_digest
                JOIN provider_runtime_authority_state runtime ON runtime.id=1
                WHERE binding.dispatch_attempt_id=?1
                  AND ?2 >= head.observed_at_high_water
                  AND NOT EXISTS (
                    SELECT 1 FROM provider_credential_clock_high_water clock
                    WHERE clock.provider_id=head.provider_id AND clock.observed_at > ?2
                  )
                  AND ?2 >= admission.issued_at AND ?2 < admission.expires_at
                  AND ?2 >= effect.effect_started_at AND ?2 < effect.effect_expires_at
                  AND ?2 < mirror.lease_expires_at AND mirror.lifecycle_state='ACTIVE'
                  AND mirror.revocation_fence < mirror.lease_fencing_token
                  AND runtime.capability_allowed=1 AND runtime.approval_allowed=1
                  AND ?2 < runtime.capability_expires_at AND ?2 < runtime.approval_expires_at
                  AND head.lifecycle_revision=binding.lifecycle_revision
                  AND head.credential_fence=binding.credential_fence
                  AND head.active_credential_version=binding.active_credential_version
                  AND head.active_ref_digest=binding.active_ref_digest
                  AND head.hard_fence_disposition IS NULL
                  AND head.release_migration_state IN ('NONE', 'CLEARED')
                  AND runtime.active=1
                  AND runtime.state_revision=admission.authority_revision
                  AND runtime.runtime_authority_id=admission.runtime_authority_id
                  AND runtime.database_generation=admission.database_generation
                  AND runtime.owner_id=admission.owner_id
                  AND runtime.expected_generation=runtime.lease_generation
                  AND runtime.expected_fencing_token=runtime.lease_fencing_token
                  AND runtime.expected_generation=admission.generation
                  AND runtime.expected_fencing_token=admission.fencing_token
                  AND binding.launch_generation=admission.generation
             )) AND (NOT EXISTS (
                SELECT 1 FROM provider_secondary_profile_attempts
                WHERE dispatch_attempt_id=?1
             ) OR EXISTS (
                SELECT 1 FROM provider_secondary_profile_attempts binding
                JOIN provider_secondary_profile_grants grant_row USING(grant_id)
                JOIN provider_secondary_profile_bindings authorization ON authorization.binding_id=binding.binding_id
                JOIN provider_execution_admissions admission ON admission.dispatch_attempt_id=binding.dispatch_attempt_id
                JOIN provider_runtime_authority_state runtime ON runtime.id=1
                WHERE binding.dispatch_attempt_id=?1 AND grant_row.enabled=1
                  AND authorization.closed_at IS NULL
                  AND authorization.grant_id=binding.grant_id
                  AND binding.profile_digest=admission.profile_digest
                  AND binding.pricing_revision_digest=admission.pricing_revision_digest
                  AND grant_row.profile_digest=admission.profile_digest
                  AND grant_row.pricing_revision_digest=admission.pricing_revision_digest
                  AND grant_row.runtime_authority_id=runtime.runtime_authority_id
                  AND grant_row.database_generation=runtime.database_generation
                  AND runtime.active=1 AND runtime.expected_generation=runtime.lease_generation
                  AND runtime.expected_fencing_token=runtime.lease_fencing_token
                  AND runtime.expected_generation=admission.generation
                  AND runtime.expected_fencing_token=admission.fencing_token
                  AND runtime.runtime_authority_id=admission.runtime_authority_id
                  AND runtime.database_generation=admission.database_generation
                  AND runtime.owner_id=authorization.owner_id
                  AND runtime.capability_allowed=1 AND runtime.approval_allowed=1
                  AND (?2 IS NULL OR (?2<runtime.capability_expires_at AND ?2<runtime.approval_expires_at))
                  AND runtime.state_revision=authorization.authority_revision
                  AND runtime.scope=authorization.scope
                  AND runtime.activation_binding_kind=authorization.activation_binding_kind
                  AND runtime.activation_binding_digest=authorization.activation_binding_digest
                  AND admission.owner_id=authorization.owner_id
                  AND admission.authority_revision=authorization.authority_revision
                  AND admission.scope=authorization.scope
                  AND admission.activation_binding_kind=authorization.activation_binding_kind
                  AND admission.activation_binding_digest=authorization.activation_binding_digest
             ))",
            params![attempt.as_bytes().as_slice(), now],
            |row| row.get(0),
        )
        .map_err(|_| ProviderStoreError::Unavailable)?;
    if current {
        Ok(())
    } else {
        Err(ProviderStoreError::StaleFencingToken)
    }
}
