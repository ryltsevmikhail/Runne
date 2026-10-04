type RemoteGrantBindingRow = (
    Vec<u8>, i64, String, String, String, Vec<u8>, Vec<u8>, i64, Option<i64>, i64, Option<i64>,
);

fn remote_local_disposition(
    transaction: &Transaction<'_>,
    record: &runne_application::provider::ProviderRemoteAttemptRecord,
    fact: Option<&runne_application::provider::ProviderRemoteAuthenticatedTerminalFact>,
) -> Result<runne_application::provider::ProviderRemoteLocalDisposition, ProviderExecutionError> {
    use runne_application::provider::ProviderRemoteLocalDisposition as Local;
    let Some(terminal) = record.terminal.as_ref() else {
        return Ok(Local::Pending);
    };
    let binding = &record.request.binding;
    let source = (
        binding.dispatch_attempt_id.as_bytes().as_slice(),
        binding.taskrun_id.as_bytes().as_slice(),
        binding.taskrun_attempt_id.as_bytes().as_slice(),
        binding.request_digest.as_slice(),
        terminal.response_id_digest.as_slice(),
        terminal.encrypted_artifact.plaintext_digest().as_slice(),
        terminal.disposition.code(),
    );
    let acknowledged_output = match remote_output_acknowledged(transaction, record, fact)? {
        Some(RemoteOutputAckProjection::PublishedOutput) => return Ok(Local::OutputApplied),
        Some(RemoteOutputAckProjection::Unverified) => return Ok(Local::Unknown),
        Some(RemoteOutputAckProjection::AuditOnly) => true,
        None => false,
    };
    let has_application: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_remote_terminal_applications
             WHERE dispatch_attempt_id=?1)",
            [source.0],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if has_application {
        if !crate::schema::v61_remote_application_matches_for_source(
            transaction,
            crate::schema::RemoteTerminalSourceMatch {
                dispatch: source.0,
                taskrun: source.1,
                attempt: source.2,
                request: source.3,
                response: source.4,
                artifact: source.5,
                status: source.6,
            },
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?
        {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        let output_applied: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_terminal_outbox
                 WHERE dispatch_attempt_id=?1 AND state=2 AND receipt_digest IS NOT NULL
                   AND applied_at IS NOT NULL)",
                [source.0],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        return Ok(if output_applied {
            Local::OutputApplied
        } else {
            Local::NoOutputApplied
        });
    }
    let has_audit: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_remote_terminal_audit_receipts
             WHERE dispatch_attempt_id=?1)",
            [source.0],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let audit_valid = if has_audit {
        crate::schema::v62_valid_audit_for_source(
            transaction,
            crate::schema::RemoteTerminalSourceMatch {
                dispatch: source.0,
                taskrun: source.1,
                attempt: source.2,
                request: source.3,
                response: source.4,
                artifact: source.5,
                status: source.6,
            },
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?
    } else {
        false
    };
    if has_audit && !audit_valid {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    if audit_valid {
        let witness: i64 = transaction
            .query_row(
                "SELECT witness_kind FROM provider_remote_terminal_audit_receipts
                 WHERE dispatch_attempt_id=?1",
                [source.0],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        return Ok(match witness {
            1 => Local::AuditOnly,
            2 => Local::Superseded,
            _ => return Err(ProviderExecutionError::JournalCorrupt),
        });
    }
    if !crate::schema::verify_v60_remote_artifact_cancel_closures(transaction)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let cancellation_closed: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_provider_cancel_fences c
             JOIN provider_remote_artifact_cancel_closures z
               ON z.dispatch_attempt_id=c.dispatch_attempt_id
              AND z.taskrun_id=c.taskrun_id AND z.taskrun_attempt_id=c.taskrun_attempt_id
              AND z.cancellation_event_id=c.cancellation_event_id
             WHERE c.dispatch_attempt_id=?1 AND c.taskrun_id=?2 AND c.taskrun_attempt_id=?3
               AND z.artifact_digest=?4 AND z.terminal_status=?5)",
            params![source.0, source.1, source.2, source.5, source.6],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    Ok(if cancellation_closed {
        Local::AcceptedCancellationClosed
    } else if acknowledged_output {
        Local::AuditOnly
    } else {
        Local::Pending
    })
}

fn remote_grant_projection(
    transaction: &Transaction<'_>,
    binding: &runne_application::provider::ProviderRemoteAttemptBinding,
) -> Result<runne_application::provider::ProviderRemoteGrantProjection, ProviderExecutionError> {
    use runne_application::provider::ProviderRemoteGrantProjection as Grant;
    let row: Option<RemoteGrantBindingRow> = transaction
        .query_row(
            "SELECT g.runtime_authority_id,g.database_generation,g.provider_id,g.profile_id,
                    g.credential_realm,g.profile_digest,g.pricing_revision_digest,g.enabled,
                    g.revoked_at,b.authority_revision,b.closed_at
             FROM provider_secondary_profile_attempts a
             JOIN provider_secondary_profile_grants g USING(grant_id)
             JOIN provider_secondary_profile_bindings b ON b.binding_id=a.binding_id
             WHERE a.dispatch_attempt_id=?1 AND a.profile_digest=?2
               AND a.pricing_revision_digest=?3",
            params![
                binding.dispatch_attempt_id.as_bytes().as_slice(),
                binding.profile_digest.as_slice(),
                binding.pricing_digest.as_slice()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let Some(row) = row else {
        let primary_admission: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions a
                 LEFT JOIN provider_secondary_profile_attempts s
                   ON s.dispatch_attempt_id=a.dispatch_attempt_id
                 WHERE a.dispatch_attempt_id=?1 AND s.dispatch_attempt_id IS NULL
                   AND a.taskrun_id=?2 AND a.execution_attempt_id=?3
                   AND a.runtime_authority_id=?4 AND a.database_generation=?5
                   AND a.profile_digest=?6 AND a.pricing_revision_digest=?7)",
                params![
                    binding.dispatch_attempt_id.as_bytes().as_slice(),
                    binding.taskrun_id.as_bytes().as_slice(),
                    binding.taskrun_attempt_id.as_bytes().as_slice(),
                    binding.runtime_authority_id.as_slice(),
                    i64::try_from(binding.database_generation)
                        .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
                    binding.profile_digest.as_slice(),
                    binding.pricing_digest.as_slice(),
                ],
                |result| result.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        return Ok(if primary_admission {
            Grant::NotSecondary
        } else {
            Grant::MissingOrMismatch
        });
    };
    if row.0.as_slice() != binding.runtime_authority_id.as_slice()
        || u64::try_from(row.1).ok() != Some(binding.database_generation)
        || row.2 != binding.provider_id
        || row.3 != binding.profile_id
        || row.4 != binding.credential_realm
        || row.5.as_slice() != binding.profile_digest.as_slice()
        || row.6.as_slice() != binding.pricing_digest.as_slice()
    {
        return Ok(Grant::MissingOrMismatch);
    }
    let current: Option<(Vec<u8>, i64, i64, i64)> = transaction
        .query_row(
            "SELECT runtime_authority_id,database_generation,state_revision,active
             FROM provider_runtime_authority_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let active = row.7 == 1
        && row.8.is_none()
        && row.10.is_none()
        && current.as_ref().is_some_and(|current| {
            current.0.as_slice() == binding.runtime_authority_id
                && u64::try_from(current.1).ok() == Some(binding.database_generation)
                && u64::try_from(current.2).ok() == Some(u64::try_from(row.9).unwrap_or(0))
                && current.3 == 1
        });
    Ok(if active {
        Grant::Active {
            authority_revision: u64::try_from(row.9)
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        }
    } else {
        Grant::Revoked {
            authority_revision: u64::try_from(row.9)
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        }
    })
}

include!("remote_terminal_effects_snapshot_credential.rs");
include!("remote_terminal_effects_snapshot_output_ack.rs");
