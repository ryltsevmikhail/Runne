use super::*;

pub(in crate::canonical_provider) fn recover_exact_cancelled_taskrun<K, S, P>(
    execution: &RuntimeProviderExecution<'_, K, S, P>,
    redaction: &dyn ProviderEventRedaction,
    store: &StoreTransaction,
    service: &dyn ConversationTextCommandService,
    taskrun_id: runne_domain::id::TaskRunId,
    cancellation_version: u64,
) -> Result<bool, ()>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: runne_runtime::provider_execution::ProviderTerminalPricing,
{
    let mut cursor = None;
    let mut matched = None;
    loop {
        let page = store
            .provider_failure_recovery_candidates(cursor, 128)
            .map_err(|_| ())?;
        for candidate in page.candidates {
            if candidate.taskrun_id == taskrun_id
                && candidate.cancellation_taskrun_version == Some(cancellation_version)
            {
                if matched.is_some() {
                    return Err(());
                }
                matched = Some(candidate);
            }
        }
        if page.reached_end {
            break;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Err(());
        }
    }
    let Some(candidate) = matched else {
        let mut unknown_cursor = None;
        let mut unknown_match = None;
        loop {
            let page = store
                .provider_unknown_failure_recovery_candidates(unknown_cursor, 128)
                .map_err(|_| ())?;
            for candidate in page.candidates {
                if candidate.taskrun_id == taskrun_id
                    && candidate.cancellation_taskrun_version == Some(cancellation_version)
                {
                    if unknown_match.is_some() {
                        return Err(());
                    }
                    unknown_match = Some(candidate);
                }
            }
            if page.reached_end {
                break;
            }
            unknown_cursor = page.next_cursor;
            if unknown_cursor.is_none() {
                return Err(());
            }
        }
        let Some(candidate) = unknown_match else {
            return Ok(false);
        };
        recover_unknown_one(execution, redaction, store, service, &candidate)?;
        return Ok(true);
    };
    recover_one(execution, redaction, store, service, &candidate)?;
    Ok(true)
}
