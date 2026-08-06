use std::path::Path;

use gocode_provider::{DispatchAttemptId, ProviderCallId, ProviderStreamId};
use gocode_store::provider::ProviderDispatchState;
use rusqlite::{Connection, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchSnapshot {
    pub(crate) attempt_id: DispatchAttemptId,
    pub(crate) call_id: ProviderCallId,
    pub(crate) permit_id: [u8; 16],
    pub(crate) token_reservation_id: [u8; 16],
    pub(crate) cost_reservation_id: [u8; 16],
    pub(crate) fencing_token: u64,
    pub(crate) provider_idempotency_key: String,
    pub(crate) prepared_digest: [u8; 32],
    pub(crate) render_digest: [u8; 32],
    pub(crate) profile_digest: [u8; 32],
    pub(crate) state: ProviderDispatchState,
    pub(crate) stream_id: Option<ProviderStreamId>,
    pub(crate) settlement_digest: Option<[u8; 32]>,
}

impl DispatchSnapshot {
    pub(crate) fn count(path: &Path, attempt_id: DispatchAttemptId) -> usize {
        let connection = Connection::open(path).unwrap();
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                params![attempt_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    }

    pub(crate) fn load(path: &Path, attempt_id: DispatchAttemptId) -> Self {
        let connection = Connection::open(path).unwrap();
        connection
            .query_row(
                "SELECT attempt_id, call_id, permit_id, token_reservation_id,
                        cost_reservation_id, fencing_token, provider_idempotency_key,
                        prepared_digest, render_digest, profile_digest, state,
                        stream_id, settlement_digest
                 FROM provider_dispatch_attempts WHERE attempt_id = ?1",
                params![attempt_id.as_bytes().as_slice()],
                |row| {
                    let state = match row.get::<_, i64>(10)? {
                        1 => ProviderDispatchState::Dispatching,
                        2 => ProviderDispatchState::RejectedBeforeEffect,
                        3 => ProviderDispatchState::Streaming,
                        4 => ProviderDispatchState::TerminalPendingCommit,
                        5 => ProviderDispatchState::Settled,
                        6 => ProviderDispatchState::Uncertain,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    Ok(Self {
                        attempt_id: DispatchAttemptId::from_bytes(fixed(row.get(0)?)),
                        call_id: ProviderCallId::from_bytes(fixed(row.get(1)?)),
                        permit_id: fixed(row.get(2)?),
                        token_reservation_id: fixed(row.get(3)?),
                        cost_reservation_id: fixed(row.get(4)?),
                        fencing_token: u64::try_from(row.get::<_, i64>(5)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        provider_idempotency_key: row.get(6)?,
                        prepared_digest: fixed(row.get(7)?),
                        render_digest: fixed(row.get(8)?),
                        profile_digest: fixed(row.get(9)?),
                        state,
                        stream_id: row
                            .get::<_, Option<Vec<u8>>>(11)?
                            .map(|value| ProviderStreamId::from_bytes(fixed(value))),
                        settlement_digest: row.get::<_, Option<Vec<u8>>>(12)?.map(fixed),
                    })
                },
            )
            .unwrap()
    }

    pub(crate) fn assert_transition(
        before: &Self,
        after: &Self,
        state: ProviderDispatchState,
        stream_id: Option<ProviderStreamId>,
        settlement_digest: Option<[u8; 32]>,
    ) {
        let mut expected = before.clone();
        expected.state = state;
        expected.stream_id = stream_id;
        expected.settlement_digest = settlement_digest;
        assert_eq!(after, &expected);
    }
}

fn fixed<const N: usize>(value: Vec<u8>) -> [u8; N] {
    value.try_into().unwrap()
}
