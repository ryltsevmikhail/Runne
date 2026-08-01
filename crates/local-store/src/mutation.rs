use super::{
    Digest, LocalStore, OptionalExtension, PreparedMutation, SecurityTransactionError, Sha256,
    TransactionBehavior, params,
};

impl LocalStore {
    /// Persists a prepared mutation before any external dispatch.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict if an operation or idempotency identity is
    /// rebound, or a storage error when the transaction cannot commit.
    #[allow(clippy::too_many_lines)]
    pub fn prepare_mutation(
        &mut self,
        mutation: &PreparedMutation<'_>,
    ) -> Result<u64, SecurityTransactionError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, String, String, String)> = transaction
            .query_row(
                "
                SELECT
                    runtime_authority,
                    principal,
                    operation_id,
                    idempotency_key,
                    target
                FROM mutation_ledger
                WHERE (runtime_authority = ?1 AND principal = ?2 AND operation_id = ?3)
                   OR (runtime_authority = ?1 AND principal = ?2 AND idempotency_key = ?4)
                ",
                params![
                    mutation.runtime_authority,
                    mutation.principal,
                    mutation.operation_id,
                    mutation.idempotency_key
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            let expected = (
                mutation.runtime_authority,
                mutation.principal,
                mutation.operation_id,
                mutation.idempotency_key,
                mutation.target,
            );
            if (
                existing.0.as_str(),
                existing.1.as_str(),
                existing.2.as_str(),
                existing.3.as_str(),
                existing.4.as_str(),
            ) != expected
            {
                return Err(SecurityTransactionError::MutationIdentityConflict);
            }
            let generation: i64 = transaction.query_row(
                "SELECT db_generation FROM meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            transaction.commit()?;
            return u64::try_from(generation)
                .map_err(|_| SecurityTransactionError::GenerationOutOfRange);
        }

        transaction.execute(
            "
            INSERT INTO mutation_ledger (
                runtime_authority,
                principal,
                operation_id,
                idempotency_key,
                target,
                disposition
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 'prepared')
            ",
            params![
                mutation.runtime_authority,
                mutation.principal,
                mutation.operation_id,
                mutation.idempotency_key,
                mutation.target
            ],
        )?;
        let mut hasher = Sha256::new();
        for field in [
            mutation.runtime_authority,
            mutation.principal,
            mutation.operation_id,
            mutation.idempotency_key,
            mutation.target,
        ] {
            hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        let digest = format!("{:x}", hasher.finalize());
        transaction.execute(
            "
            UPDATE meta
            SET db_generation = db_generation + 1,
                last_transaction_digest = ?1,
                commit_marker = 1
            WHERE singleton = 1
            ",
            params![digest],
        )?;
        let database_generation: i64 = transaction.query_row(
            "SELECT db_generation FROM meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        u64::try_from(database_generation)
            .map_err(|_| SecurityTransactionError::GenerationOutOfRange)
    }
}
