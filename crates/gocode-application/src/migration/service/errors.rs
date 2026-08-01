fn rollback_disposition_tag(disposition: RollbackDisposition) -> u8 {
    match disposition {
        RollbackDisposition::Eligible => 1,
        RollbackDisposition::Ineligible => 2,
    }
}

fn map_store_error(error: MigrationStoreError) -> MigrationError {
    match error {
        MigrationStoreError::PlanVersionConflict { expected, actual } => {
            MigrationError::PlanVersionConflict { expected, actual }
        }
        MigrationStoreError::RoutingGenerationConflict { expected, actual } => {
            MigrationError::RoutingGenerationConflict { expected, actual }
        }
        MigrationStoreError::ArithmeticOverflow => MigrationError::ArithmeticOverflow,
        MigrationStoreError::LifecycleAuthorityRequired { .. } => MigrationError::DrainBlocked,
        MigrationStoreError::CorruptData
        | MigrationStoreError::UnsupportedSchema
        | MigrationStoreError::Unavailable
        | MigrationStoreError::IdempotencyConflict
        | MigrationStoreError::IntegrityViolation
        | MigrationStoreError::RuntimeBindingConflict
        | MigrationStoreError::DispatchIntentConflict
        | MigrationStoreError::InvalidDispatchTransition => {
            MigrationError::StorageContractViolation
        }
    }
}
