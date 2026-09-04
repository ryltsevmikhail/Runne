fn authorized_legacy_read() -> runne_provider::AuthorizedCredentialLegacyRead {
    legacy_read_with_verifier().0
}

fn legacy_read_with_verifier() -> (runne_provider::AuthorizedCredentialLegacyRead,
    runne_provider::CredentialLegacyReadVerifier) {
    use runne_provider::{
        CredentialMaterial, CredentialMutationGrant, CredentialRuntimeMutationPlan,
        CredentialServiceCorrelation, CredentialServiceDeadline, CredentialServiceEpoch,
        CredentialServiceProtocolCodec, CredentialServiceRequestSequence,
    };
    let command = command(CredentialOperationAction::MigrateLegacy);
    let channel = channel();
    let binding = binding(9);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let authorization = authorization(&issuer, &command, binding, &channel);
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let grant = CredentialMutationGrant::generate().unwrap();
    let plan = CredentialRuntimeMutationPlan::issue(
        &store.runtime_arm_authority(), command,
        CredentialServiceEpoch::from_bytes([2; 16]).unwrap(),
        [3; 32], [4; 16], 5, binding,
        CredentialServiceRequestSequence::new(1).unwrap(),
        CredentialServiceCorrelation::from_bytes([7; 16]).unwrap(),
        CredentialServiceDeadline::new(10, 20).unwrap(), grant.digest(),
    ).unwrap();
    let (_, writer) = plan.split();
    let handoff = CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer, grant)
        .unwrap().into_transport_bytes();
    let mut captured = None;
    CredentialServiceProtocolCodec::decode_authenticated_writer_legacy_handoff(
        &handoff, authorization, &effects, &channel, binding,
        |read| {
            captured = Some(read);
            CredentialMaterial::from_bytes(b"fixture-only".to_vec()).and_then(|material| runne_provider::CredentialLegacySourceMaterial::new(material, [73; 16]))
        },
    ).unwrap();
    (captured.unwrap(), effects.legacy_read_verifier(binding, &channel))
}
