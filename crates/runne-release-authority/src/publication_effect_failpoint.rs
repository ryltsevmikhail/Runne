//! Deterministic one-shot persistence/response cuts compiled only into unit tests.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationEffectFailpoint {
    AfterRenameBeforeParentSync,
    BeforeClaimSave,
    AfterClaimSave,
    AfterInFlightSave,
    BeforeSettlementSave,
    AfterSettlementSave,
    AfterUncertainSave,
    AfterReconcileSave,
}
