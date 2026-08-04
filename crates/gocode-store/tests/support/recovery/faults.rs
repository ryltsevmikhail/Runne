use gocode_store::provider::{
    MarkProviderStreaming, ProviderClaimOutcome, ProviderDispatchClaim, ProviderDispatchState,
    SettleProviderDispatch, SqliteProviderDispatchStore,
};

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

pub(crate) struct RecoveryFaultDecorator<'a> {
    store: &'a SqliteProviderDispatchStore,
    provider: &'a CountingProvider,
    fault: RecoveryFaultPoint,
}

impl<'a> RecoveryFaultDecorator<'a> {
    pub(crate) fn new(
        store: &'a SqliteProviderDispatchStore,
        provider: &'a CountingProvider,
        fault: RecoveryFaultPoint,
    ) -> Self {
        Self {
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
        let outcome = self
            .store
            .claim(request)
            .map_err(|_| RecoveryTestDisposition::StoreRejected)?;
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
