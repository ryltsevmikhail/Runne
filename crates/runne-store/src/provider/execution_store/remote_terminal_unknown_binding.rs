struct UnknownGrantExpectation<'a> {
    attempt_id: DispatchAttemptId,
    provider_id: &'a str,
    provider_idempotency_key: &'a str,
    owner_id: &'a str,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    profile_digest: [u8; 32],
    pricing_revision_digest: [u8; 32],
}

type UnknownGrantBindingRow = (
    Vec<u8>, String, String, String, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>, String, i64,
    String, String, Vec<u8>, i64, Option<i64>, Option<i64>, String, Vec<u8>, Vec<u8>, String,
);

fn unknown_grant_binding(
    connection: &Connection,
    expected: UnknownGrantExpectation<'_>,
) -> Result<(Option<[u8; 32]>, bool), ProviderExecutionError> {
    let row: Option<UnknownGrantBindingRow> = connection
        .query_row(
            "SELECT g.grant_id,g.provider_id,g.profile_id,g.credential_realm,g.profile_digest,
                    g.pricing_revision_digest,g.runtime_authority_id,g.database_generation,
                    b.binding_id,b.owner_id,b.authority_revision,b.scope,b.activation_binding_kind,
                    b.activation_binding_digest,g.enabled,g.revoked_at,b.closed_at,
                    a.provider_idempotency_key,a.profile_digest,a.pricing_revision_digest,g.provider_id
             FROM provider_secondary_profile_attempts a
             JOIN provider_secondary_profile_grants g ON g.grant_id=a.grant_id
             JOIN provider_secondary_profile_bindings b ON b.binding_id=a.binding_id
              AND b.grant_id=a.grant_id
             JOIN provider_execution_admissions admission
               ON admission.dispatch_attempt_id=a.dispatch_attempt_id
              AND admission.provider_idempotency_key=a.provider_idempotency_key
              AND admission.profile_digest=a.profile_digest
              AND admission.pricing_revision_digest=a.pricing_revision_digest
              AND admission.profile_digest=g.profile_digest
              AND admission.pricing_revision_digest=g.pricing_revision_digest
              AND admission.owner_id=b.owner_id
              AND admission.authority_revision=b.authority_revision
              AND admission.scope=b.scope
              AND admission.activation_binding_kind=b.activation_binding_kind
              AND admission.activation_binding_digest=b.activation_binding_digest
             WHERE a.dispatch_attempt_id=?1",
            [expected.attempt_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?,
                    row.get(15)?, row.get(16)?, row.get(17)?, row.get(18)?, row.get(19)?,
                    row.get(20)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let Some(row) = row else {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_secondary_profile_attempts WHERE dispatch_attempt_id=?1)",
            [expected.attempt_id.as_bytes().as_slice()], |item| item.get(0),
        ).map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        return if exists {
            Err(ProviderExecutionError::JournalCorrupt)
        } else {
            Ok((None, true))
        };
    };
    if row.1 != expected.provider_id
        || row.3 != expected.provider_id
        || row.6.as_slice() != expected.runtime_authority_id
        || unknown_positive_u64(row.7)? != expected.database_generation
        || row.9 != expected.owner_id
        || row.17 != expected.provider_idempotency_key
        || unknown_fixed_bytes::<32>(row.18.clone())? != expected.profile_digest
        || unknown_fixed_bytes::<32>(row.19.clone())? != expected.pricing_revision_digest
        || row.20 != expected.provider_id
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let mut hash = Sha256::new();
    hash.update(b"GOCODE_PROVIDER_UNKNOWN_GRANT_PIN_V1\0");
    for value in [
        &row.0[..],
        row.1.as_bytes(),
        row.2.as_bytes(),
        row.3.as_bytes(),
        &row.4,
        &row.5,
        &row.6,
        &row.8,
        row.9.as_bytes(),
        row.11.as_bytes(),
        row.12.as_bytes(),
        &row.13,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(row.7.to_be_bytes());
    hash.update(row.10.to_be_bytes());
    let active = row.14 == 1 && row.15.is_none() && row.16.is_none();
    Ok((Some(hash.finalize().into()), active))
}
