//! SQLite adapter атомарной pre-effect транзакции.

use std::path::Path;
use std::sync::Mutex;

use gocode_application::security::atomic_transaction::{
    AtomicPreEffectTransaction, AtomicTransactionError, AuthorizationDecision,
    DispatchIntentRecord, IntentStatus, PreEffectTransactionOutcome,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::schema::{apply_migrations, open_with_pragmas, run_startup_gates};

/// Repository-owned SQLite store для security pre-effect boundary.
pub struct SqliteAtomicPreEffectStore {
    connection: Mutex<Connection>,
}

impl SqliteAtomicPreEffectStore {
    /// Открывает store, применяет migrations и fail-closed возвращает ошибку.
    pub fn open(path: &Path) -> Result<Self, AtomicTransactionError> {
        let path = path
            .to_str()
            .ok_or(AtomicTransactionError::StoreUnavailable)?;
        let connection =
            open_with_pragmas(path).map_err(|_| AtomicTransactionError::StoreUnavailable)?;
        apply_migrations(&connection).map_err(|_| AtomicTransactionError::StoreUnavailable)?;
        run_startup_gates(&connection, path)
            .map_err(|_| AtomicTransactionError::StoreUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Атомарно фиксирует authorization, budget, audit, intent и permit claim.
    pub fn commit_pre_effect(
        &self,
        transaction: &AtomicPreEffectTransaction,
    ) -> Result<PreEffectTransactionOutcome, AtomicTransactionError> {
        validate_transaction(transaction)?;
        if !transaction.authorization_decision.allowed {
            return Ok(PreEffectTransactionOutcome::RolledBack {
                reason: transaction.authorization_decision.reason.clone(),
            });
        }

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| AtomicTransactionError::StoreUnavailable)?;
        let sqlite = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AtomicTransactionError::StoreUnavailable)?;

        if let Some(stored) = load_transaction_by_permit(&sqlite, &transaction.permit_id)? {
            if stored.dispatch_intent != transaction.dispatch_intent {
                return Err(AtomicTransactionError::PermitIntentConflict);
            }
            if stored != *transaction {
                return Err(AtomicTransactionError::ReplayConflict);
            }
            return Ok(PreEffectTransactionOutcome::Committed {
                intent_id: transaction.dispatch_intent.clone(),
            });
        }
        if load_transaction_by_intent(&sqlite, &transaction.dispatch_intent)?.is_some() {
            return Err(AtomicTransactionError::ReplayConflict);
        }

        insert_all(&sqlite, transaction)?;
        sqlite
            .commit()
            .map_err(|_| AtomicTransactionError::StoreUnavailable)?;
        Ok(PreEffectTransactionOutcome::Committed {
            intent_id: transaction.dispatch_intent.clone(),
        })
    }

    /// Загружает recovery projection dispatch intent.
    pub fn get_dispatch_intent(
        &self,
        intent_id: &str,
    ) -> Result<Option<DispatchIntentRecord>, AtomicTransactionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AtomicTransactionError::StoreUnavailable)?;
        connection
            .query_row(
                "SELECT intent.intent_id, intent.status,
                        (SELECT COUNT(*) FROM security_authorization_decisions WHERE intent_id = ?1),
                        (SELECT COUNT(*) FROM security_budget_consumptions WHERE intent_id = ?1),
                        (SELECT COUNT(*) FROM security_audit_pre_effect WHERE intent_id = ?1),
                        (SELECT COUNT(*) FROM security_permit_claims WHERE intent_id = ?1)
                 FROM security_dispatch_intents intent WHERE intent.intent_id = ?1",
                [intent_id],
                |row| {
                    let status: String = row.get(1)?;
                    let component_counts = [
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ];
                    if status != "uncertain" || component_counts != [1, 1, 1, 1] {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    Ok(DispatchIntentRecord {
                        intent_id: row.get(0)?,
                        status: IntentStatus::Uncertain,
                    })
                },
            )
            .optional()
            .map_err(|_| AtomicTransactionError::CorruptData)
    }

    /// Проверяет durable permit claim.
    pub fn permit_is_claimed(&self, permit_id: &str) -> Result<bool, AtomicTransactionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AtomicTransactionError::StoreUnavailable)?;
        connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM security_permit_claims WHERE permit_id = ?1
                 )",
                [permit_id],
                |row| row.get(0),
            )
            .map_err(|_| AtomicTransactionError::CorruptData)
    }

    /// Возвращает число полностью зафиксированных transactions.
    pub fn committed_count(&self) -> Result<u64, AtomicTransactionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AtomicTransactionError::StoreUnavailable)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM security_dispatch_intents",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AtomicTransactionError::CorruptData)?;
        u64::try_from(count).map_err(|_| AtomicTransactionError::CorruptData)
    }
}

fn validate_transaction(
    transaction: &AtomicPreEffectTransaction,
) -> Result<(), AtomicTransactionError> {
    if transaction.budget_reservation_id.is_empty() || transaction.budget_amount == 0 {
        return Err(AtomicTransactionError::BudgetUnavailable);
    }
    if !transaction.side_effect_started
        || transaction.dispatch_intent.is_empty()
        || transaction.permit_id.is_empty()
        || transaction.authorization_decision.grant_id.is_empty()
        || transaction.authorization_decision.reason.is_empty()
    {
        return Err(AtomicTransactionError::IncompleteTransaction);
    }
    Ok(())
}

fn insert_all(
    sqlite: &Transaction<'_>,
    transaction: &AtomicPreEffectTransaction,
) -> Result<(), AtomicTransactionError> {
    let intent = &transaction.dispatch_intent;
    sqlite
        .execute(
            "INSERT INTO security_dispatch_intents (intent_id, status)
             VALUES (?1, 'uncertain')",
            [intent],
        )
        .and_then(|_| {
            sqlite.execute(
                "INSERT INTO security_authorization_decisions
                 (intent_id, grant_id, allowed, reason) VALUES (?1, ?2, ?3, ?4)",
                params![
                    intent,
                    transaction.authorization_decision.grant_id,
                    transaction.authorization_decision.allowed,
                    transaction.authorization_decision.reason
                ],
            )
        })
        .and_then(|_| {
            sqlite.execute(
                "INSERT INTO security_budget_consumptions (intent_id, reservation_id, amount)
                 VALUES (?1, ?2, ?3)",
                params![
                    intent,
                    transaction.budget_reservation_id,
                    transaction.budget_amount
                ],
            )
        })
        .and_then(|_| {
            sqlite.execute(
                "INSERT INTO security_audit_pre_effect (intent_id, side_effect_started)
                 VALUES (?1, 1)",
                [intent],
            )
        })
        .and_then(|_| {
            sqlite.execute(
                "INSERT INTO security_permit_claims (permit_id, intent_id) VALUES (?1, ?2)",
                params![transaction.permit_id, intent],
            )
        })
        .map_err(|_| AtomicTransactionError::StoreUnavailable)?;
    Ok(())
}

fn load_transaction_by_permit(
    sqlite: &Transaction<'_>,
    permit_id: &str,
) -> Result<Option<AtomicPreEffectTransaction>, AtomicTransactionError> {
    load_transaction(sqlite, "WHERE permit.permit_id = ?1", permit_id)
}

fn load_transaction_by_intent(
    sqlite: &Transaction<'_>,
    intent_id: &str,
) -> Result<Option<AtomicPreEffectTransaction>, AtomicTransactionError> {
    load_transaction(sqlite, "WHERE intent.intent_id = ?1", intent_id)
}

fn load_transaction(
    sqlite: &Transaction<'_>,
    predicate: &str,
    value: &str,
) -> Result<Option<AtomicPreEffectTransaction>, AtomicTransactionError> {
    let sql = format!(
        "SELECT auth.grant_id, auth.allowed, auth.reason, budget.reservation_id, budget.amount,
                 audit.side_effect_started, intent.intent_id, permit.permit_id
         FROM security_dispatch_intents intent
         JOIN security_authorization_decisions auth USING (intent_id)
         JOIN security_budget_consumptions budget USING (intent_id)
         JOIN security_audit_pre_effect audit USING (intent_id)
         JOIN security_permit_claims permit USING (intent_id)
         {predicate}"
    );
    sqlite
        .query_row(&sql, [value], |row| {
            Ok(AtomicPreEffectTransaction {
                authorization_decision: AuthorizationDecision {
                    grant_id: row.get(0)?,
                    allowed: row.get(1)?,
                    reason: row.get(2)?,
                },
                budget_reservation_id: row.get(3)?,
                budget_amount: row.get(4)?,
                side_effect_started: row.get(5)?,
                dispatch_intent: row.get(6)?,
                permit_id: row.get(7)?,
            })
        })
        .optional()
        .map_err(|_| AtomicTransactionError::CorruptData)
}
