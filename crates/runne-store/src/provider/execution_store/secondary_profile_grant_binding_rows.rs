type GrantRow = (
    [u8; 16],
    [u8; 16],
    u64,
    [u8; 16],
    String,
    u64,
    String,
    String,
    [u8; 32],
    String,
    String,
    String,
    [u8; 32],
    [u8; 32],
    u64,
    u64,
);
pub(in crate::provider::execution_store) fn load_by_profile(
    transaction: &Transaction<'_>,
    spec: &ProviderSecondaryProfileGrantSpec,
) -> Result<Option<GrantRow>, ProviderAdmissionError> {
    transaction.query_row(
        "SELECT g.grant_id,g.runtime_authority_id,g.database_generation,b.binding_id,b.owner_id,b.authority_revision,b.scope,
                b.activation_binding_kind,b.activation_binding_digest,g.provider_id,g.profile_id,g.credential_realm,
                g.profile_digest,g.pricing_revision_digest,g.token_budget_limit,g.cost_budget_limit_micros
         FROM provider_secondary_profile_grants g JOIN provider_secondary_profile_bindings b USING(grant_id)
         WHERE g.provider_id=?1 AND g.profile_id=?2 ORDER BY b.closed_at IS NULL DESC,b.created_at DESC LIMIT 1",
        params![spec.provider_id(),spec.profile_id()], |r| Ok((fixed_bytes(r,0)?,fixed_bytes(r,1)?,read_u64(r,2)?,fixed_bytes(r,3)?,r.get(4)?,read_u64(r,5)?,r.get(6)?,r.get(7)?,fixed_bytes(r,8)?,r.get(9)?,r.get(10)?,r.get(11)?,fixed_bytes(r,12)?,fixed_bytes(r,13)?,read_u64(r,14)?,read_u64(r,15)?)),
    ).optional().map_err(|_|ProviderAdmissionError::RepositoryFailure)
}
pub(in crate::provider::execution_store) fn capability_from_row(
    row: GrantRow,
    spec: ProviderSecondaryProfileGrantSpec,
) -> Result<ProviderSecondaryProfileGrant, ProviderAdmissionError> {
    if row.9 != spec.provider_id()
        || row.10 != spec.profile_id()
        || row.11 != spec.credential_realm()
        || row.12 != spec.profile_digest()
        || row.13 != spec.pricing_revision_digest()
        || row.14 != spec.token_budget_limit()
        || row.15 != spec.cost_budget_limit_micros()
    {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(ProviderSecondaryProfileGrant {
        grant_id: row.0,
        authority_id: row.1,
        database_generation: row.2,
        binding_id: row.3,
        owner_id: row.4,
        authority_revision: row.5,
        scope: row.6,
        activation_binding_kind: row.7,
        activation_binding_digest: row.8,
        spec,
    })
}
pub(in crate::provider::execution_store) fn validate_spec_row(
    tx: &Transaction<'_>,
    grant: &ProviderSecondaryProfileGrant,
    spec: &ProviderSecondaryProfileGrantSpec,
) -> Result<(), ProviderAdmissionError> {
    let ok=tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_secondary_profile_grants WHERE grant_id=?1 AND enabled=1
        AND runtime_authority_id=?2 AND database_generation=?3 AND provider_id=?4 AND profile_id=?5 AND credential_realm=?6
        AND profile_digest=?7 AND pricing_revision_digest=?8 AND token_budget_limit=?9 AND cost_budget_limit_micros=?10)",
        params![grant.grant_id.as_slice(),grant.authority_id.as_slice(),i64_value(grant.database_generation)?,spec.provider_id(),spec.profile_id(),spec.credential_realm(),spec.profile_digest().as_slice(),spec.pricing_revision_digest().as_slice(),i64_value(spec.token_budget_limit())?,i64_value(spec.cost_budget_limit_micros())?],|r|r.get::<_,bool>(0)).map_err(|_|ProviderAdmissionError::RepositoryFailure)?;
    if ok {
        Ok(())
    } else {
        Err(ProviderAdmissionError::AuthorityDenied)
    }
}
pub(in crate::provider::execution_store) fn capability_is_active(
    tx: &Transaction<'_>,
    grant: [u8; 16],
    binding: [u8; 16],
) -> Result<bool, ProviderAdmissionError> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_secondary_profile_grants g JOIN provider_secondary_profile_bindings b USING(grant_id) WHERE g.grant_id=?1 AND g.enabled=1 AND b.binding_id=?2 AND b.closed_at IS NULL)",params![grant.as_slice(),binding.as_slice()],|r|r.get(0)).map_err(|_|ProviderAdmissionError::RepositoryFailure)
}
pub(in crate::provider::execution_store) fn capability_is_enabled(
    tx: &Transaction<'_>,
    grant: [u8; 16],
) -> Result<bool, ProviderAdmissionError> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_secondary_profile_grants WHERE grant_id=?1 AND enabled=1)",[grant.as_slice()],|r|r.get(0)).map_err(|_|ProviderAdmissionError::RepositoryFailure)
}

pub(in crate::provider::execution_store) fn exact_revoked_spec(
    tx: &Transaction<'_>,
    grant: [u8; 16],
    spec: &ProviderSecondaryProfileGrantSpec,
) -> Result<bool, ProviderAdmissionError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_secondary_profile_grants
         WHERE grant_id=?1 AND enabled=0 AND revoked_at IS NOT NULL
           AND provider_id=?2 AND profile_id=?3 AND credential_realm=?4
           AND profile_digest=?5 AND pricing_revision_digest=?6
           AND token_budget_limit=?7 AND cost_budget_limit_micros=?8)",
        params![
            grant.as_slice(),
            spec.provider_id(),
            spec.profile_id(),
            spec.credential_realm(),
            spec.profile_digest().as_slice(),
            spec.pricing_revision_digest().as_slice(),
            i64_value(spec.token_budget_limit())?,
            i64_value(spec.cost_budget_limit_micros())?
        ],
        |row| row.get(0),
    )
    .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}
fn fixed_bytes<const N: usize>(row: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<[u8; N]> {
    row.get::<_, Vec<u8>>(i)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(in crate::provider::execution_store) fn read_u64(
    row: &rusqlite::Row<'_>,
    i: usize,
) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(i)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(in crate::provider::execution_store) fn i64_value(
    v: u64,
) -> Result<i64, ProviderAdmissionError> {
    i64::try_from(v).map_err(|_| ProviderAdmissionError::InvalidSemanticContext)
}
pub(in crate::provider::execution_store) fn random_id() -> [u8; 16] {
    loop {
        let mut id = [0; 16];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::fill_bytes(&mut rng, &mut id);
        if id != [0; 16] {
            return id;
        }
    }
}

pub(in crate::provider::execution_store) fn insert_binding(
    tx: &Transaction<'_>,
    grant_id: [u8; 16],
    state: &RuntimeAuthorityState,
    now: i64,
) -> Result<[u8; 16], ProviderAdmissionError> {
    let binding = random_id();
    let kind = state
        .activation_binding_kind
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    tx.execute("INSERT INTO provider_secondary_profile_bindings(binding_id,grant_id,owner_id,authority_revision,scope,activation_binding_kind,activation_binding_digest,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![binding.as_slice(),grant_id.as_slice(),state.owner_id,i64_value(state.state_revision)?,state.scope,kind.code(),state.activation_binding_digest.as_slice(),now]).map_err(|_|ProviderAdmissionError::RepositoryFailure)?;
    Ok(binding)
}
