use super::{
    state::MigrationPhase,
    types::{GateFamily, RoutingGeneration},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    PlanNotFound,
    InvalidPhaseTransition {
        from: MigrationPhase,
        to: MigrationPhase,
    },
    SpecializedTransitionRequired {
        target: MigrationPhase,
    },
    TerminalPlanImmutable,
    PlanVersionConflict {
        expected: u64,
        actual: u64,
    },
    RoutingGenerationConflict {
        expected: RoutingGeneration,
        actual: RoutingGeneration,
    },
    RoutingUnitMismatch,
    ExpectedRoutingGenerationRequired,
    GateMissing {
        family: GateFamily,
    },
    GateFailed {
        family: GateFamily,
    },
    GateExpired {
        family: GateFamily,
    },
    GateRevoked {
        family: GateFamily,
    },
    GateSetChanged,
    PreparedCutoverNotFound,
    EvidenceMissingForPhase {
        target: MigrationPhase,
    },
    EvidenceProvesMutation {
        target: MigrationPhase,
    },
    EvidenceScopeMismatch,
    AuditUnavailable,
    DrainIncomplete,
    DrainTimedOut,
    UnresolvedEffect,
    StaleFencingToken,
    UnsupportedFeatureProfile,
    ProductionGatesUnavailable,
    ObservationWindowIncomplete,
    ImportAmbiguous,
    RollbackIneligible,
    ReverseMigrationUnavailable,
    EmergencyRevokeIneligible,
    RetirementBlocked,
    DrainBlocked,
    StorageContractViolation,
    ArithmeticOverflow,
}
