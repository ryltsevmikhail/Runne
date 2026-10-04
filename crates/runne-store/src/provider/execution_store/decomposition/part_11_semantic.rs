fn execution_semantic_digest(request: &ProviderAuthorityIssueRequest) -> [u8; 32] {
    execution_semantic_digest_source(&ExecutionSemanticSource {
        principal_id: &request.principal_id,
        conversation_id: request.conversation_id.as_bytes(),
        taskrun_id: request.taskrun_id.as_bytes(),
        execution_attempt_id: request.execution_attempt_id.as_bytes(),
        call_id: request.prepared.call_id.as_bytes(),
        call_digest_version: request.prepared.call_digest_version,
        prepared_digest: request.prepared.prepared_digest,
        render_digest: request.prepared.render_digest,
        profile_digest: request.prepared.profile_digest,
        pricing_revision_digest: request.pricing_revision_digest,
        requested_input_tokens: request.requested_input_tokens,
        requested_output_tokens: request.requested_output_tokens,
        max_cost_micros: request.max_cost_micros,
        currency: &request.currency,
        provider_idempotency_key: &request.provider_idempotency_key,
    })
}

pub(crate) struct ExecutionSemanticSource<'a> {
    pub(crate) principal_id: &'a str,
    pub(crate) conversation_id: &'a [u8; 16],
    pub(crate) taskrun_id: &'a [u8; 16],
    pub(crate) execution_attempt_id: &'a [u8; 16],
    pub(crate) call_id: &'a [u8; 16],
    pub(crate) call_digest_version: ProviderCallDigestVersion,
    pub(crate) prepared_digest: [u8; 32],
    pub(crate) render_digest: [u8; 32],
    pub(crate) profile_digest: [u8; 32],
    pub(crate) pricing_revision_digest: [u8; 32],
    pub(crate) requested_input_tokens: u64,
    pub(crate) requested_output_tokens: u64,
    pub(crate) max_cost_micros: u64,
    pub(crate) currency: &'a str,
    pub(crate) provider_idempotency_key: &'a str,
}

pub(crate) fn execution_semantic_digest_source(source: &ExecutionSemanticSource<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_EXECUTION_SEMANTIC_V1);
    hash_text(&mut hasher, source.principal_id);
    hasher.update(source.conversation_id);
    hasher.update(source.taskrun_id);
    hasher.update(source.execution_attempt_id);
    hasher.update(source.call_id);
    hasher.update([match source.call_digest_version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    }]);
    hasher.update(source.prepared_digest);
    hasher.update(source.render_digest);
    hasher.update(source.profile_digest);
    hasher.update(source.pricing_revision_digest);
    hasher.update(source.requested_input_tokens.to_be_bytes());
    hasher.update(source.requested_output_tokens.to_be_bytes());
    hasher.update(source.max_cost_micros.to_be_bytes());
    hash_text(&mut hasher, source.currency);
    hash_text(&mut hasher, source.provider_idempotency_key);
    hasher.finalize().into()
}

fn hash_text(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_be_bytes());
    hasher.update(text.as_bytes());
}
