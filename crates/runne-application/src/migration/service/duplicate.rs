impl<S, H> MigrationService<S, H>
where
    S: MigrationControlStore,
    H: ShadowExecutionPort,
{
    fn lookup_duplicate(
        &self,
        context: &MigrationCommandContext,
        fingerprint: &MigrationCommandFingerprint,
    ) -> Result<Option<MigrationCommandOutcome>, MigrationError> {
        match self
            .store
            .lookup_receipt(context, fingerprint)
            .map_err(map_store_error)?
        {
            MigrationReceiptLookup::Miss => Ok(None),
            MigrationReceiptLookup::Duplicate { stored_result } => Ok(Some(*stored_result)),
        }
    }

}
