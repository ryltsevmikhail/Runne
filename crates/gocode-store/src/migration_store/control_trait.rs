impl MigrationControlStore for SqliteMigrationControlStore {
    fn load_plan(
        &self,
        plan_id: &gocode_application::migration::types::MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationStoreError> {
        self.load_plan_impl(plan_id)
    }

    fn load_routing_head(
        &self,
        unit: &RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationStoreError> {
        let connection = self.reader()?;
        load_routing_head_on(&connection, unit)
    }

    fn lookup_receipt(
        &self,
        context: &MigrationCommandContext,
        fingerprint: &MigrationCommandFingerprint,
    ) -> Result<MigrationReceiptLookup, MigrationStoreError> {
        let connection = self.reader()?;
        lookup_receipt_on(&connection, context, fingerprint)
    }

    fn commit(
        &self,
        commit: MigrationCommit,
    ) -> Result<MigrationCommitResult, MigrationStoreError> {
        reject_uncertified_lifecycle_mutations(&commit)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)?;
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_write_error)?;

        match lookup_receipt_on(&transaction, commit.context(), commit.fingerprint())? {
            MigrationReceiptLookup::Duplicate { stored_result } => {
                return Ok(MigrationCommitResult::Duplicate {
                    stored_result: *stored_result,
                });
            }
            MigrationReceiptLookup::Miss => {}
        }

        validate_plan_guard(&transaction, &commit)?;
        validate_routing_guard(&transaction, &commit)?;
        validate_mutations(&commit)?;
        persist_mutations(&transaction, &commit)?;
        persist_result_plan(&transaction, &commit)?;
        persist_audit(&transaction, &commit)?;
        persist_receipt(&transaction, &commit)?;
        transaction.commit().map_err(map_write_error)?;

        let receipt = MigrationReceipt {
            command_id: commit.context().command_id,
            idempotency_key: commit.context().idempotency_key.clone(),
            fingerprint: *commit.fingerprint(),
            stored_result: commit.outcome().clone(),
            committed_at: commit.audit().recorded_at,
        };
        Ok(MigrationCommitResult::Committed { receipt })
    }
}
