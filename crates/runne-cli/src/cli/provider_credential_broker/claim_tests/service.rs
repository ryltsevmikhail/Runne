use runne_provider::{
    CredentialBindingDigest, CredentialMutationGrant, CredentialRuntimeMutationPlan,
    CredentialServiceCorrelation, CredentialServiceDeadline, CredentialServiceEpoch,
    CredentialServiceProtocolCodec, CredentialServiceRequestSequence,
    CredentialWriterAuthorityPair,
};

use super::super::claim::claim_writer_authorization_with_service_parts;
use super::*;

#[test]
fn v3_claim_requires_and_retains_the_exact_service_handoff_after_ack() {
    let command = command(16, CredentialOperationAction::Pair);
    let (mut parts, written) = endpoint(
        issue(command.clone(), binding(), [11; 32]),
        Some(accepted(&command)),
    );
    parts
        .control
        .input
        .get_mut()
        .extend_from_slice(&service_handoff(command.clone()));
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();

    let claimed = claim_writer_authorization_with_service_parts(
        parts.control,
        parts.channel,
        parts.ticket,
        &issuer,
        effects,
        CredentialSecretInputPresence::Present,
        writer_service_configuration(),
    );

    assert!(claimed.is_ok());
    assert_one_claim(&written, true);

    let (parts, _) = endpoint(
        issue(command.clone(), binding(), [11; 32]),
        Some(accepted(&command)),
    );
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    assert!(
        claim_writer_authorization_with_service_parts(
            parts.control,
            parts.channel,
            parts.ticket,
            &issuer,
            effects,
            CredentialSecretInputPresence::Present,
            writer_service_configuration(),
        )
        .is_err()
    );
}

fn service_handoff(command: CredentialBrokerCommand) -> Vec<u8> {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let grant = CredentialMutationGrant::generate().unwrap();
    let plan = CredentialRuntimeMutationPlan::issue(
        &store.runtime_arm_authority(),
        command,
        CredentialServiceEpoch::from_bytes([2; 16]).unwrap(),
        [3; 32],
        [4; 16],
        5,
        CredentialBindingDigest::from_measured([6; 32]).unwrap(),
        CredentialServiceRequestSequence::new(1).unwrap(),
        CredentialServiceCorrelation::from_bytes([7; 16]).unwrap(),
        CredentialServiceDeadline::new(10, 20).unwrap(),
        grant.digest(),
    )
    .unwrap();
    let (_, writer) = plan.split();
    CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer, grant)
        .unwrap()
        .into_transport_bytes()
        .to_vec()
}

fn writer_service_configuration() -> runne_macos_xpc::CredentialServiceEndpointConfiguration {
    let requirement = |identifier: &str, hash: char| {
        runne_macos_xpc::CredentialServicePeerRequirement::new(format!(
            "identifier \"{identifier}\" and anchor apple generic and certificate leaf[subject.OU] = \"758F9Z45SR\" and cdhash H\"{}\"",
            hash.to_string().repeat(40)
        ))
        .unwrap()
    };
    runne_macos_xpc::CredentialServiceEndpointConfiguration::new(
        runne_macos_xpc::CredentialServiceEndpointRole::Writer,
        runne_macos_xpc::CredentialServiceEndpointRole::Writer.endpoint_name(),
        requirement("com.runne.credential-service", '4'),
        requirement("runne", '2'),
    )
    .unwrap()
}
