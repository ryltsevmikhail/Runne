use super::super::*;
use runne_application::provider::{ProviderTerminalApplicationKind, ProviderTerminalOutboxRecord};
use runne_domain::id::IntegrityDigest;
use runne_provider::DispatchAttemptId;
use runne_store::store::taskrun_tool_invocation::ToolSourceRef;

pub(super) fn load(
    store: &dyn runne_application::provider::ProviderExecutionStore,
    attempt_id: DispatchAttemptId,
    profile_digest: [u8; 32],
    runtime_generation: u64,
) -> Result<Option<D2ToolTerminalRef>, CanonicalProviderExecutionError> {
    let records = store
        .pending_tool_proposal_outbox_for_attempt(attempt_id)
        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
    let mut matches = records.into_iter().filter(|record| {
        record.application_kind == ProviderTerminalApplicationKind::ToolProposal
            && record.attempt_id == attempt_id
            && record.profile_digest == profile_digest
            && record.runtime_generation == runtime_generation
    });
    let Some(record) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    Ok(Some(terminal_ref(&record)))
}

pub(super) fn sources(
    store: &dyn runne_application::provider::ProviderExecutionStore,
    attempt_id: DispatchAttemptId,
    profile_digest: [u8; 32],
    runtime_generation: u64,
    required_event_kind: u8,
    max_calls: usize,
) -> Result<Vec<ToolSourceRef>, CanonicalProviderExecutionError> {
    if !matches!(required_event_kind, 4 | 7) {
        return Err(CanonicalProviderExecutionError::Conflict);
    }
    let records = store
        .load_encrypted_events(attempt_id)
        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
    let terminal = load(store, attempt_id, profile_digest, runtime_generation)?
        .ok_or(CanonicalProviderExecutionError::Uncertain)?;
    let mut sources = Vec::with_capacity(2);
    for row in records {
        if row.profile_digest != profile_digest || row.runtime_generation != runtime_generation {
            return Err(CanonicalProviderExecutionError::Uncertain);
        }
        let include = (row.event_kind == required_event_kind && !row.terminal)
            || (row.event_kind == 5 && row.terminal && row.sequence == terminal.terminal_sequence);
        if include {
            sources.push(ToolSourceRef {
                dispatch_attempt_id: *row.attempt_id.as_bytes(),
                sequence: row.sequence,
                event_kind: row.event_kind,
                terminal: row.terminal,
                plaintext_digest: IntegrityDigest::from_bytes(*row.encrypted.plaintext_digest()),
                profile_digest: IntegrityDigest::from_bytes(row.profile_digest),
                runtime_generation: row.runtime_generation,
            });
        }
    }
    if !valid_terminal_sources_bounded(&sources, required_event_kind, max_calls) {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    Ok(sources)
}

#[cfg(test)]
fn valid_terminal_sources(sources: &[ToolSourceRef], required_event_kind: u8) -> bool {
    valid_terminal_sources_bounded(sources, required_event_kind, 1)
}
fn valid_terminal_sources_bounded(
    sources: &[ToolSourceRef],
    required_event_kind: u8,
    max_calls: usize,
) -> bool {
    let terminal_count = sources
        .iter()
        .filter(|source| source.event_kind == 5 && source.terminal)
        .count();
    terminal_count == 1
        && if required_event_kind == 4 {
            (1..=16).contains(&max_calls)
                && (2..=max_calls + 1).contains(&sources.len())
                && sources
                    .iter()
                    .filter(|source| source.event_kind == 4 && !source.terminal)
                    .count()
                    == sources.len() - 1
        } else {
            required_event_kind == 7
                && sources.len() <= 32
                && sources.iter().all(|source| {
                    (source.event_kind == 7 && !source.terminal)
                        || (source.event_kind == 5 && source.terminal)
                })
                && sources
                    .windows(2)
                    .all(|pair| pair[0].sequence < pair[1].sequence)
        }
}

fn terminal_ref(record: &ProviderTerminalOutboxRecord) -> D2ToolTerminalRef {
    D2ToolTerminalRef {
        attempt_id: record.attempt_id,
        outbox_id: record.outbox_id,
        terminal_sequence: record.terminal_sequence,
        settlement_digest: record.settlement_digest,
        fencing_token: record.fencing_token,
        call_digest_version: record.call_digest_version,
        profile_digest: record.profile_digest,
        runtime_generation: record.runtime_generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(event_kind: u8, terminal: bool, sequence: u64) -> ToolSourceRef {
        ToolSourceRef {
            dispatch_attempt_id: [1; 16],
            sequence,
            event_kind,
            terminal,
            plaintext_digest: IntegrityDigest::from_bytes([2; 32]),
            profile_digest: IntegrityDigest::from_bytes([3; 32]),
            runtime_generation: 1,
        }
    }

    #[test]
    fn final_stop_sources_allow_ordered_scanner_progress_then_terminal() {
        assert!(valid_terminal_sources(
            &[source(7, false, 3), source(7, false, 4), source(5, true, 5)],
            7,
        ));
        assert!(valid_terminal_sources(&[source(5, true, 5)], 7));
        assert!(!valid_terminal_sources(
            &[source(4, false, 4), source(5, true, 5)],
            7
        ));
        assert!(valid_terminal_sources(
            &[source(4, false, 4), source(5, true, 5)],
            4
        ));
        assert!(!valid_terminal_sources(
            &[source(4, false, 3), source(7, false, 4), source(5, true, 5)],
            7
        ));
    }
}
