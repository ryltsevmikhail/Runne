fn request_matches_anchored_command(
    request: &MutationRequest,
    command: &runne_local_store::NormalizedMutationCommand,
) -> Result<(), AppCoreError> {
    (request.ledger_command()? == *command)
        .then_some(())
        .ok_or(AppCoreError::MutationUnavailable)
}

include!("mutation_reconcile/request.rs");

include!("mutation_reconcile/outcome.rs");

include!("mutation_reconcile/runtime.rs");
