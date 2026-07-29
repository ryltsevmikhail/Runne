/// Classification of an OpenCode operation relative to GOCODE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompatibilityClass {
    /// Побайтово идентичный wire контракт.
    Exact,
    /// Семантически эквивалентен, требует translation.
    Translated,
    /// Семантическая совместимость с оговоренными отличиями.
    Semantic,
    /// Семантически несовместим в данной версии профиля.
    Incompatible,
    /// Операция существует в baseline, но не в этом профиле.
    Unsupported,
}

/// Implementation progress of a compatibility target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImplementationStatus {
    Planned,
    Implemented,
    Verified,
}

/// Reason a translation request was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectionCode {
    OperationPlanned,
    OperationUnsupported,
    UnknownOperation,
    ProfileMismatch,
    SchemaMismatch,
    InventoryIntegrityFailure,
}

/// Architectural rationale for why a route is Unsupported in this profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectionRationale {
    MissingConversationAggregate,
    MissingPromptExecution,
    MissingModelExecution,
    MissingReadModel,
    MissingCancelUseCase,
    MissingMessageAggregate,
    MissingCapabilityEngine,
    MissingFileManagement,
    MissingCheckpointAdapter,
    MissingPtyGateway,
    MissingMcpGateway,
    MissingLspGateway,
}

/// Confidence level of the reverse-spec observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Confidence {
    Observed,
    Inferred,
    Reported,
}
