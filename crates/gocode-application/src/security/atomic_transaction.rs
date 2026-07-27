//! Контракты атомарной pre-effect транзакции.

/// Полный набор данных, который должен быть зафиксирован до внешнего эффекта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicPreEffectTransaction {
    /// Решение авторизации.
    pub authorization_decision: AuthorizationDecision,
    /// Идентификатор подтверждённой бюджетной reservation.
    pub budget_reservation_id: String,
    /// Объём подтверждённой бюджетной reservation.
    pub budget_amount: u64,
    /// Маркер `SideEffectStarted`.
    pub side_effect_started: bool,
    /// Стабильный идентификатор dispatch intent.
    pub dispatch_intent: String,
    /// Идентификатор одноразового permit.
    pub permit_id: String,
}

/// Авторизационное решение, вошедшее в pre-effect transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    /// Capability grant, по которому принято решение.
    pub grant_id: String,
    /// Разрешён ли эффект.
    pub allowed: bool,
    /// Стабильная причина решения.
    pub reason: String,
}

/// Результат атомарной фиксации.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreEffectTransactionOutcome {
    /// Все пять записей зафиксированы.
    Committed {
        /// Зафиксированный dispatch intent.
        intent_id: String,
    },
    /// Авторизация запретила эффект до мутации repository.
    RolledBack {
        /// Причина отказа.
        reason: String,
    },
}

impl PreEffectTransactionOutcome {
    /// Возвращает intent для committed outcome или причину rollback.
    pub fn intent_id(&self) -> &str {
        match self {
            Self::Committed { intent_id } => intent_id,
            Self::RolledBack { reason } => reason,
        }
    }
}

/// Статус durable dispatch intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentStatus {
    /// Pre-effect commit завершён, но post-effect evidence отсутствует.
    Uncertain,
}

/// Durable projection dispatch intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchIntentRecord {
    /// Идентификатор intent.
    pub intent_id: String,
    /// Recovery status.
    pub status: IntentStatus,
}

/// Ошибки атомарной pre-effect транзакции.
#[derive(Debug, PartialEq, Eq)]
pub enum AtomicTransactionError {
    /// Permit уже связан с другим intent.
    PermitIntentConflict,
    /// Retry изменил ранее зафиксированную семантику.
    ReplayConflict,
    /// Обязательное поле или marker отсутствует.
    IncompleteTransaction,
    /// Budget reservation не была consumed.
    BudgetUnavailable,
    /// Repository недоступен.
    StoreUnavailable,
    /// Durable данные нарушают контракт.
    CorruptData,
}

impl core::fmt::Display for AtomicTransactionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::PermitIntentConflict => "permit was already claimed for a different intent",
            Self::ReplayConflict => "idempotent replay changed the committed transaction",
            Self::IncompleteTransaction => "pre-effect transaction is incomplete",
            Self::BudgetUnavailable => "budget unavailable",
            Self::StoreUnavailable => "atomic transaction store unavailable",
            Self::CorruptData => "atomic transaction store contains corrupt data",
        })
    }
}

impl std::error::Error for AtomicTransactionError {}
