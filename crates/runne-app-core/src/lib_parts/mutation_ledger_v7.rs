include!("mutation_ledger_v7/command.rs");

fn ledger_identity(
    binding: MutationAdmissionBinding,
    request: &MutationRequest,
) -> Result<runne_local_store::MutationIdentity, AppCoreError> {
    runne_local_store::MutationIdentity::new(
        binding.runtime_identity_digest,
        binding.principal_digest,
        request.operation,
        request.target.kind(),
        request.target.canonical_id().clone(),
        request.idempotency_key.clone(),
        request.expected_version,
        request.semantic_digest(),
    )
    .map_err(|_| AppCoreError::InvalidMutation)
}
