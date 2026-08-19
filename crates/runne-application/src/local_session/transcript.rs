/// Transitional non-wire transcript helper retained for internal callers.
///
/// It delegates to the sole v3 prefix-free encoder; production HTTP and
/// runne-runtime-client bootstrap use the timestamp-bound v3 operations directly.
pub fn bootstrap_proof_transcript(
    binding: &RuntimeSessionBinding,
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
) -> Vec<u8> {
    let stable = binding.stable();
    let instance = binding.ephemeral().daemon_instance_id().into_bytes();
    let generation = binding.ephemeral().launch_generation().to_be_bytes();
    let fields: [&[u8]; 16] = [
        BOOTSTRAP_PROTOCOL_V3,
        stable.authority_id(),
        stable.principal_id().as_str().as_bytes(),
        stable.lineage_id().as_bytes(),
        stable.profile_id().as_bytes(),
        stable.schema_hash(),
        binding.certificate_sha256(),
        &instance,
        &generation,
        binding.ephemeral().session_id(),
        BOOTSTRAP_FINAL_ENDPOINT_V3,
        BOOTSTRAP_HTTP_METHOD_V3,
        &[],
        &[],
        &client_nonce,
        &[],
    ];
    runne_pairing_crypto::encode_final_transcript(
        &runne_pairing_crypto::BootstrapTranscriptV3 {
            key_version: BOOTSTRAP_KEY_VERSION_V3,
            fields,
        },
        server_nonce,
    )
    .expect("fixed local-session fields fit the canonical transcript")
}
