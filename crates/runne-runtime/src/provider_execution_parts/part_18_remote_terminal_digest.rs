fn remote_terminal_settlement_digest(
    snapshot: &runne_application::provider::ProviderRemoteAttemptRecord,
    artifact: &runne_provider::ProviderRemoteTerminalArtifact,
    status: ProviderRemoteTerminalDisposition,
    usage: ProviderUsage,
    charge_micros: u64,
    currency: &str,
) -> [u8; 32] {
    use sha2::Digest as _;
    let binding = &snapshot.request.binding;
    let mut hash = sha2::Sha256::new();
    hash.update(b"GOCODE_PROVIDER_REMOTE_SETTLEMENT_V1\0");
    hash.update(binding.dispatch_attempt_id.as_bytes());
    hash.update(binding.taskrun_id.as_bytes());
    hash.update(binding.taskrun_attempt_id.as_bytes());
    hash.update(binding.request_digest);
    hash.update(artifact.response_id().as_str().as_bytes());
    hash.update([status.code() as u8]);
    hash.update(snapshot.terminal.as_ref().map_or([0; 32], |terminal| {
        *terminal.encrypted_artifact.plaintext_digest()
    }));
    hash.update(usage.input_tokens().to_be_bytes());
    hash.update(usage.output_tokens().to_be_bytes());
    hash.update(usage.cached_input_tokens().to_be_bytes());
    hash.update(usage.reasoning_output_tokens().to_be_bytes());
    hash.update(charge_micros.to_be_bytes());
    hash.update(currency.as_bytes());
    hash.finalize().into()
}
