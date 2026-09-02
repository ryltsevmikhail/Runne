use super::super::{
    CredentialMutationGrant, CredentialMutationGrantDigest, CredentialRuntimeMutationArmRequest,
    CredentialRuntimeMutationPlan, CredentialServiceCorrelation, CredentialServiceDeadline,
    CredentialServiceEpoch, CredentialServiceProtocolCodec, CredentialServiceRequest,
    CredentialServiceRequestSequence, CredentialWriterServiceBindingHandoff,
};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget,
    CredentialEnrollmentAuthorityPair, CredentialEnrollmentStoreAuthority, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialRuntimeArmAuthority, CredentialTicketAttempt,
};
use crate::{CredentialVersionRef, ProviderId};

#[allow(clippy::too_many_arguments)]
pub(super) fn encoded_arm(
    operation: u8,
    attempt: u64,
    provider: u8,
    version: u64,
    revision: u64,
    fence: u64,
    release: u8,
    sequence: u64,
    issued: u64,
    expires: u64,
    grant: u8,
) -> Vec<u8> {
    CredentialServiceProtocolCodec::encode_request(CredentialServiceRequest::RuntimeMutationArm(
        arm_with_grant(
            operation,
            attempt,
            provider,
            version,
            revision,
            fence,
            release,
            sequence,
            issued,
            expires,
            CredentialMutationGrant::from_wire([grant; 32])
                .unwrap()
                .digest(),
        ),
    ))
    .unwrap()
    .test_bytes()
    .to_vec()
}

pub(super) fn encoded_arm_security(
    epoch: u8,
    session: u8,
    generation: u64,
    action: CredentialOperationAction,
    provider_number: u8,
    version: u64,
) -> Vec<u8> {
    let provider = ProviderId::new(format!("provider-{provider_number}")).unwrap();
    let command = CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        action,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, version).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    let (authority, _) = authorities();
    let arm = CredentialRuntimeMutationPlan::issue(
        &authority,
        command,
        CredentialServiceEpoch::from_bytes([epoch; 16]).unwrap(),
        [5; 32],
        [session; 16],
        generation,
        digest(1),
        CredentialServiceRequestSequence::new(1).unwrap(),
        CredentialServiceCorrelation::from_bytes([6; 16]).unwrap(),
        CredentialServiceDeadline::new(10, 20).unwrap(),
        CredentialMutationGrant::from_wire([8; 32])
            .unwrap()
            .digest(),
    )
    .unwrap()
    .split()
    .0;
    CredentialServiceProtocolCodec::encode_request(CredentialServiceRequest::RuntimeMutationArm(
        arm,
    ))
    .unwrap()
    .test_bytes()
    .to_vec()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn arm_with_grant(
    operation: u8,
    attempt: u64,
    provider: u8,
    version: u64,
    revision: u64,
    fence: u64,
    release: u8,
    sequence: u64,
    issued: u64,
    expires: u64,
    grant: CredentialMutationGrantDigest,
) -> CredentialRuntimeMutationArmRequest {
    let provider = ProviderId::new(format!("provider-{provider}")).unwrap();
    let command = CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        CredentialTicketAttempt::new(attempt).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, version).unwrap()),
        CredentialLifecycleRevision::new(revision).unwrap(),
        CredentialFence::new(fence).unwrap(),
        None,
    )
    .unwrap();
    let (authority, _) = authorities();
    CredentialRuntimeMutationPlan::issue(
        &authority,
        command,
        CredentialServiceEpoch::from_bytes([1; 16]).unwrap(),
        [5; 32],
        [2; 16],
        3,
        digest(release),
        CredentialServiceRequestSequence::new(sequence).unwrap(),
        CredentialServiceCorrelation::from_bytes([6; 16]).unwrap(),
        CredentialServiceDeadline::new(issued, expires).unwrap(),
        grant,
    )
    .unwrap()
    .split()
    .0
}

pub(super) fn writer_plan_with_grant(
    grant: CredentialMutationGrantDigest,
) -> (
    CredentialBrokerCommand,
    CredentialRuntimeMutationArmRequest,
    CredentialWriterServiceBindingHandoff,
) {
    let provider = ProviderId::new("provider-1").unwrap();
    let command = CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    let (authority, _) = authorities();
    let plan = CredentialRuntimeMutationPlan::issue(
        &authority,
        command.clone(),
        CredentialServiceEpoch::from_bytes([1; 16]).unwrap(),
        [5; 32],
        [2; 16],
        3,
        digest(1),
        CredentialServiceRequestSequence::new(1).unwrap(),
        CredentialServiceCorrelation::from_bytes([6; 16]).unwrap(),
        CredentialServiceDeadline::new(10, 20).unwrap(),
        grant,
    )
    .unwrap();
    let (arm, handoff) = plan.split();
    (command, arm, handoff)
}

pub(super) fn arm_request_with_correlation(correlation: u8) -> CredentialServiceRequest {
    let provider = ProviderId::new("provider-1").unwrap();
    let command = CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    let (authority, _) = authorities();
    let arm = CredentialRuntimeMutationPlan::issue(
        &authority,
        command,
        CredentialServiceEpoch::from_bytes([1; 16]).unwrap(),
        [5; 32],
        [2; 16],
        3,
        digest(1),
        CredentialServiceRequestSequence::new(1).unwrap(),
        CredentialServiceCorrelation::from_bytes([correlation; 16]).unwrap(),
        CredentialServiceDeadline::new(10, 20).unwrap(),
        CredentialMutationGrant::from_wire([8; 32])
            .unwrap()
            .digest(),
    )
    .unwrap()
    .split()
    .0;
    CredentialServiceRequest::RuntimeMutationArm(arm)
}

pub(super) fn authorities() -> (
    CredentialRuntimeArmAuthority,
    CredentialEnrollmentStoreAuthority,
) {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let arm = store.runtime_arm_authority();
    (arm, store)
}

pub(super) fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
