/// Exact binary bootstrap-proof transcript. No JSON canonicalization is used.
pub fn bootstrap_proof_transcript(
    binding: &RuntimeSessionBinding,
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
) -> Vec<u8> {
    let stable = binding.stable();
    let mut output = b"gocode/local-runtime/bootstrap-proof/v2\0".to_vec();
    output.extend_from_slice(&2_u32.to_be_bytes());
    output.extend_from_slice(binding.certificate_sha256());
    output.extend_from_slice(&server_nonce);
    output.extend_from_slice(&client_nonce);
    output.extend_from_slice(stable.authority_id());
    append_string(&mut output, stable.principal_id().as_str());
    output.extend_from_slice(stable.lineage_id().as_bytes());
    output.extend_from_slice(&binding.ephemeral().daemon_instance_id().into_bytes());
    output.extend_from_slice(&binding.ephemeral().launch_generation().to_be_bytes());
    append_string(&mut output, stable.profile_id());
    output.extend_from_slice(stable.schema_hash());
    output.extend_from_slice(stable.capability_digest());
    output
}

fn append_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &(u16::try_from(value.len()).expect("API identity and profile are bounded")).to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}
