use super::*;

#[test]
fn oauth_pair_accepts_native_envelope_above_legacy_capacity() {
    let command = oauth_command(5, 9);
    let binding = binding();
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let native = PairNative::ready();
    let material = native.material.clone();
    let writer = BrokeredProviderCredentialWriterAdapter::new(effects, native, access());
    let input = BrokeredCreateInput::new(command.clone(), binding, channel.clone()).unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": "runne.oauth-import/v1",
        "provider": "github-copilot",
        "access_token": "x".repeat(MAX_PROVIDER_CREDENTIAL_BYTES + 900),
        "refresh_token": null,
        "account_id": null,
        "expires_at_unix_seconds": 4_000_000_000u64
    }))
    .unwrap();
    assert!(payload.len() > MAX_PROVIDER_CREDENTIAL_BYTES);
    let fixture =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, payload).unwrap();

    writer
        .create_sealed_exact(
            authorization(&issuer, &command, binding, &channel),
            input,
            fixture.pending,
            fixture.envelope,
        )
        .unwrap();
    assert!(material.lock().unwrap().as_ref().unwrap().len() > MAX_PROVIDER_CREDENTIAL_BYTES);
}
