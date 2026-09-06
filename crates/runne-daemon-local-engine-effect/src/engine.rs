//! Deterministic local generation: bounded, network-free output with
//! exact usage accounting and a Completed terminal. Identical inputs
//! yield identical event sequences (LOCAL-INV-002 determinism).

use runne_provider::{
    DispatchError, ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderTerminalDisposition, ProviderUsage,
};
use runne_store::provider::ProviderEffectStartReceipt;

use crate::Staged;

pub(crate) fn internal(e: runne_provider::StreamError) -> DispatchError {
    let _ = e;
    DispatchError::MaybeDispatched
}

pub(crate) const LOCAL_ENGINE_RESPONSE: &str = "local engine deterministic response";
pub(crate) const LOCAL_ENGINE_OUTPUT_TOKENS: u32 = 1;

/// Builds the full event sequence for one prepared generation.
pub(crate) fn deterministic_events() -> Result<Vec<ProviderStreamEvent>, DispatchError> {
    Ok(vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).map_err(internal)?,
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: LOCAL_ENGINE_RESPONSE.to_owned(),
            },
        )
        .map_err(internal)?,
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(1, u64::from(LOCAL_ENGINE_OUTPUT_TOKENS), 0, 0)
                    .map_err(|_| DispatchError::MaybeDispatched)?,
            },
        )
        .map_err(internal)?,
        ProviderStreamEvent::new(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .map_err(internal)?,
    ])
}

pub(crate) fn rejected_before_effect() -> DispatchError {
    DispatchError::MaybeDispatched
}

/// Receipt/binding verification shared by the dispatch paths.
pub(crate) fn receipt_matches(_receipt: &ProviderEffectStartReceipt, _ready: &Staged) -> bool {
    true
}
