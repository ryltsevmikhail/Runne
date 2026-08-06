use std::path::{Path, PathBuf};

use gocode_store::provider::{
    MarkProviderStreaming, ProviderClaimOutcome, ProviderDispatchClaim, ProviderDispatchState,
    SettleProviderDispatch, SqliteProviderDispatchStore,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::CountingProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryFaultPoint {
    BeforeClaim,
    AfterClaimBeforeDispatch,
    AfterSimulatedDispatchBeforeStreaming,
    AfterStreamingBeforeSettle,
    AfterSettleBeforeAcknowledgement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryTestDisposition {
    Injected(RecoveryFaultPoint),
    StoreRejected,
}

/// Reproduces the retired caller-selected claim path directly against SQLite.
///
/// The runtime-owned V13 admission issuer owns production claims
/// (`LegacyClaimDisabled`), so recovery tests materialize the durable attempt
/// row with the same single-use CAS semantics the old store claim provided:
/// an existing attempt is replayed exactly, otherwise a fresh row is inserted
/// with `state = 1` (Dispatching).
pub(crate) fn claim_dispatch_row(
    path: &Path,
    claim: &ProviderDispatchClaim,
) -> ProviderClaimOutcome {
    let connection = Connection::open(path).unwrap();
    let existing = connection
        .query_row(
            "SELECT state FROM provider_dispatch_attempts WHERE attempt_id = ?1",
            [claim.attempt_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .unwrap();
    if let Some(state) = existing {
        let state = match state {
            1 => ProviderDispatchState::Dispatching,
            2 => ProviderDispatchState::RejectedBeforeEffect,
            3 => ProviderDispatchState::Streaming,
            4 => ProviderDispatchState::TerminalPendingCommit,
            5 => ProviderDispatchState::Settled,
            6 => ProviderDispatchState::Uncertain,
            _ => panic!("unexpected durable dispatch state {state}"),
        };
        return ProviderClaimOutcome::Existing {
            attempt_id: claim.attempt_id,
            state,
        };
    }
    connection
        .execute(
            "INSERT INTO provider_dispatch_attempts
             (attempt_id, call_id, permit_id, token_reservation_id,
              cost_reservation_id, fencing_token, provider_idempotency_key,
              prepared_digest, render_digest, profile_digest, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.call_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                i64::try_from(claim.fencing_token).unwrap(),
                claim.provider_idempotency_key,
                claim.prepared_digest.as_slice(),
                claim.render_digest.as_slice(),
                claim.profile_digest.as_slice(),
            ],
        )
        .unwrap();
    ProviderClaimOutcome::Winner {
        permit_id: claim.permit_id,
    }
}

pub(crate) struct RecoveryFaultDecorator<'a> {
    path: PathBuf,
    store: &'a SqliteProviderDispatchStore,
    provider: &'a CountingProvider,
    fault: RecoveryFaultPoint,
}

impl<'a> RecoveryFaultDecorator<'a> {
    pub(crate) fn new(
        path: PathBuf,
        store: &'a SqliteProviderDispatchStore,
        provider: &'a CountingProvider,
        fault: RecoveryFaultPoint,
    ) -> Self {
        Self {
            path,
            store,
            provider,
            fault,
        }
    }

    pub(crate) fn claim(
        &self,
        request: &ProviderDispatchClaim,
    ) -> Result<ProviderClaimOutcome, RecoveryTestDisposition> {
        if self.fault == RecoveryFaultPoint::BeforeClaim {
            return Err(RecoveryTestDisposition::Injected(self.fault));
        }
        let outcome = claim_dispatch_row(&self.path, request);
        if self.fault == RecoveryFaultPoint::AfterClaimBeforeDispatch {
            return Err(RecoveryTestDisposition::Injected(self.fault));
        }
        if matches!(outcome, ProviderClaimOutcome::Winner { .. }) {
            self.provider.simulate_dispatch();
        }
        Ok(outcome)
    }

    pub(crate) fn mark_streaming(
        &self,
        request: &MarkProviderStreaming,
    ) -> Result<ProviderDispatchState, RecoveryTestDisposition> {
        if self.fault == RecoveryFaultPoint::AfterSimulatedDispatchBeforeStreaming {
            return Err(RecoveryTestDisposition::Injected(self.fault));
        }
        let state = self
            .store
            .mark_streaming(request)
            .map_err(|_| RecoveryTestDisposition::StoreRejected)?;
        if self.fault == RecoveryFaultPoint::AfterStreamingBeforeSettle {
            return Err(RecoveryTestDisposition::Injected(self.fault));
        }
        Ok(state)
    }

    pub(crate) fn settle(
        &self,
        request: &SettleProviderDispatch,
    ) -> Result<ProviderDispatchState, RecoveryTestDisposition> {
        let state = self
            .store
            .settle(request)
            .map_err(|_| RecoveryTestDisposition::StoreRejected)?;
        if self.fault == RecoveryFaultPoint::AfterSettleBeforeAcknowledgement {
            return Err(RecoveryTestDisposition::Injected(self.fault));
        }
        Ok(state)
    }
}
