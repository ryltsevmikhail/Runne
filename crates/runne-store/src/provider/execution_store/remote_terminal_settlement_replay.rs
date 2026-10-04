struct AccountedRemoteSourceFacts<'a> {
    request: &'a runne_runtime::provider_execution::ProviderRemoteTerminalSourceCommit,
    state: i64,
    usage: (Option<i64>, Option<i64>, Option<i64>, Option<i64>),
    financial: (Option<i64>, Option<&'a str>, Option<&'a [u8]>),
    application_receipt: Option<&'a [u8]>,
    has_usage: bool,
    outbox_required: bool,
}

fn validate_accounted_remote_source(
    transaction: &Transaction<'_>,
    facts: AccountedRemoteSourceFacts<'_>,
) -> Result<(), ProviderExecutionError> {
    let AccountedRemoteSourceFacts {
        request,
        state,
        usage,
        financial,
        application_receipt,
        has_usage,
        outbox_required,
    } = facts;
    let (charge, currency, digest) = financial;
    if !has_usage
        || charge.is_none()
        || currency.is_none()
        || digest.is_none()
        || (state == 2 && application_receipt.is_some())
        || (state == 4 && application_receipt.is_none())
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let valid: bool = if outbox_required {
        transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_accounting_settlements a
             JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
             WHERE a.dispatch_attempt_id=?1 AND a.input_tokens IS ?2
               AND a.output_tokens IS ?3 AND a.cached_input_tokens IS ?4
               AND a.reasoning_output_tokens IS ?5 AND a.charge_micros=?6
               AND a.currency=?7 AND a.settlement_digest=?8
               AND o.terminal_sequence=0 AND o.plaintext_digest=?9
               AND o.settlement_digest=?8
               AND ((?10=2 AND o.state=1 AND o.receipt_digest IS NULL
                      AND o.applied_at IS NULL)
                 OR (?10=4 AND o.state=2 AND o.receipt_digest=?11
                      AND o.applied_at IS NOT NULL)))",
            rusqlite::params![
                request.attempt_id().as_bytes().as_slice(),
                usage.0,
                usage.1,
                usage.2,
                usage.3,
                charge,
                currency,
                digest,
                request.artifact_digest().as_slice(),
                state,
                application_receipt,
            ],
            |row| row.get(0),
        )
    } else {
        transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_accounting_settlements a
             WHERE a.dispatch_attempt_id=?1 AND a.input_tokens IS ?2
               AND a.output_tokens IS ?3 AND a.cached_input_tokens IS ?4
               AND a.reasoning_output_tokens IS ?5 AND a.charge_micros=?6
               AND a.currency=?7 AND a.settlement_digest=?8)",
            rusqlite::params![
                request.attempt_id().as_bytes().as_slice(),
                usage.0,
                usage.1,
                usage.2,
                usage.3,
                charge,
                currency,
                digest,
            ],
            |row| row.get(0),
        )
    }
    .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if valid {
        Ok(())
    } else {
        Err(ProviderExecutionError::TerminalConflict)
    }
}

fn source_delivery_allowed(
    request: &runne_runtime::provider_execution::ProviderRemoteTerminalSourceCommit,
    verified: &crate::store::taskrun_submit_origin::VerifiedRemoteTerminalTaskRunSource,
) -> bool {
    request.terminal_status()
        == runne_application::provider::ProviderRemoteTerminalDisposition::Completed
        && request.output_digest().is_some()
        && verified.publication_allowed
        && request.publication_disposition()
            == runne_provider::ProviderRemotePublicationDisposition::Allowed
}
