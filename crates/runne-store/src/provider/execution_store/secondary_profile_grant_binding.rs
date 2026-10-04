use super::*;

impl ProviderSecondaryProfileGrant {
    pub(in crate::provider::execution_store) fn verify_for_issue(
        &self,
        transaction: &Transaction<'_>,
        state: &RuntimeAuthorityState,
        request: &ProviderAuthorityIssueRequest,
        now: i64,
    ) -> Result<(), ProviderAdmissionError> {
        verify_grant_owner(self, state)?;
        validate_state(state, &self.spec)?;
        if !state.active || state.principal_id != request.principal_id {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        if state.expected_generation != state.lease_generation
            || state.expected_fencing_token != state.lease_fencing_token
        {
            return Err(ProviderAdmissionError::StaleFencingToken);
        }
        if !state.capability_allowed {
            return Err(if state.capability_revocation_observed {
                ProviderAdmissionError::CapabilityRevoked
            } else {
                ProviderAdmissionError::CapabilityDenied
            });
        }
        if state.capability_expires_at <= now {
            return Err(ProviderAdmissionError::CapabilityExpired);
        }
        if !state.approval_allowed {
            return Err(if state.approval_revocation_observed {
                ProviderAdmissionError::ApprovalRevoked
            } else {
                ProviderAdmissionError::ApprovalDenied
            });
        }
        if state.approval_expires_at <= now {
            return Err(ProviderAdmissionError::ApprovalExpired);
        }
        if request.provider_id.as_str() != self.spec.provider_id()
            || request.prepared.profile_digest != self.spec.profile_digest()
            || request.pricing_revision_digest != self.spec.pricing_revision_digest()
            || !capability_is_active(transaction, self.grant_id, self.binding_id)?
        {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        validate_spec_row(transaction, self, &self.spec)
    }
}

pub(in crate::provider::execution_store) fn verify_secondary_attempt_binding(
    transaction: &Transaction<'_>,
    attempt: runne_provider::DispatchAttemptId,
    profile_digest: [u8; 32],
    pricing_digest: [u8; 32],
    require_active: bool,
) -> Result<bool, ProviderExecutionError> {
    let row: Option<AttemptBindingRow> = transaction.query_row(
        "SELECT g.runtime_authority_id,g.database_generation,g.profile_digest,g.pricing_revision_digest,
                a.profile_digest,a.pricing_revision_digest,auth.owner_id,auth.authority_revision,auth.scope,
                auth.activation_binding_kind,auth.activation_binding_digest,auth.closed_at,g.enabled
         FROM provider_secondary_profile_attempts binding
         JOIN provider_secondary_profile_grants g USING(grant_id)
         JOIN provider_secondary_profile_bindings auth ON auth.binding_id=binding.binding_id
         JOIN provider_execution_admissions a ON a.dispatch_attempt_id=binding.dispatch_attempt_id
         WHERE binding.dispatch_attempt_id=?1 AND binding.grant_id=auth.grant_id",
        [attempt.as_bytes().as_slice()], |r| Ok(AttemptBindingRow {
            authority_id: fixed_bytes(r,0)?, db_generation: read_u64(r,1)?, grant_profile: fixed_bytes(r,2)?,
            grant_pricing: fixed_bytes(r,3)?, admission_profile: fixed_bytes(r,4)?, admission_pricing: fixed_bytes(r,5)?,
            owner: r.get(6)?, revision: read_u64(r,7)?, scope: r.get(8)?, kind: r.get(9)?,
            activation_digest: fixed_bytes(r,10)?, closed_at: r.get(11)?, enabled: r.get(12)?,
        }),
    ).optional().map_err(|_|ProviderExecutionError::StoreUnavailable)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let state = super::super::load_runtime_authority(transaction)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?
        .ok_or(ProviderExecutionError::StaleGeneration)?;
    if row.grant_profile != profile_digest
        || row.grant_pricing != pricing_digest
        || row.admission_profile != profile_digest
        || row.admission_pricing != pricing_digest
        || row.authority_id != state.runtime_authority_id
        || row.db_generation != state.database_generation
    {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    if require_active
        && (row.enabled != 1
            || row.closed_at.is_some()
            || row.owner != state.owner_id
            || row.revision != state.state_revision
            || row.scope != state.scope
            || Some(row.kind.as_str()) != state.activation_binding_kind.map(|k| k.code())
            || row.activation_digest != state.activation_binding_digest)
    {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(true)
}

struct AttemptBindingRow {
    authority_id: [u8; 16],
    db_generation: u64,
    grant_profile: [u8; 32],
    grant_pricing: [u8; 32],
    admission_profile: [u8; 32],
    admission_pricing: [u8; 32],
    owner: String,
    revision: u64,
    scope: String,
    kind: String,
    activation_digest: [u8; 32],
    closed_at: Option<i64>,
    enabled: i64,
}

pub(super) fn validate_state(
    state: &RuntimeAuthorityState,
    spec: &ProviderSecondaryProfileGrantSpec,
) -> Result<(), ProviderAdmissionError> {
    if !state.active
        || !state.capability_allowed
        || !state.approval_allowed
        || state.activation_binding_kind.is_none()
        || state.activation_binding_digest == [0; 32]
        || state.owner_id.is_empty()
        || state.scope.is_empty()
        || spec.provider_id() != spec.credential_realm()
    {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    Ok(())
}

pub(in crate::provider::execution_store) fn verify_grant_owner(
    grant: &ProviderSecondaryProfileGrant,
    state: &RuntimeAuthorityState,
) -> Result<(), ProviderAdmissionError> {
    if grant.authority_id != state.runtime_authority_id
        || grant.database_generation != state.database_generation
        || grant.owner_id != state.owner_id
        || grant.authority_revision != state.state_revision
        || grant.scope != state.scope
        || grant.activation_binding_digest != state.activation_binding_digest
        || Some(grant.activation_binding_kind.as_str())
            != state.activation_binding_kind.map(|k| k.code())
    {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }
    Ok(())
}
pub(in crate::provider::execution_store) fn same_owner(
    grant: &ProviderSecondaryProfileGrant,
    state: &RuntimeAuthorityState,
) -> bool {
    verify_grant_owner(grant, state).is_ok()
}

include!("secondary_profile_grant_binding_rows.rs");
