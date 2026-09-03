use runne_provider::{
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerTarget,
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialLifecycleRevision,
    CredentialMutationGrant, CredentialMutationGrantDigest, CredentialOperationAction,
    CredentialOperationId, CredentialRuntimeMutationPlan, CredentialServiceCorrelation,
    CredentialServiceDeadline, CredentialServiceEpoch, CredentialServiceProtocolCodec,
    CredentialServiceRequest, CredentialServiceRequestSequence, CredentialTicketAttempt,
    CredentialVersionRef, CredentialWriterAuthorityPair, ProviderId, sealed_pair_for_test,
};

use super::{EPOCH, SESSION, auth, digest};

pub(in crate::tests) fn mutation_frames(
    id: u8,
    sequence: u64,
    key: u8,
    action: CredentialOperationAction,
) -> (Vec<u8>, Vec<u8>, CredentialMutationGrant) {
    let grant = CredentialMutationGrant::generate().unwrap();
    let command = command(id, action);
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let plan = mutation_plan(
        &store,
        command.clone(),
        super::OWNER,
        sequence,
        id,
        grant.digest(),
    );
    let (arm, handoff_binding) = plan.split();
    let arm = runtime_frame(key, CredentialServiceRequest::RuntimeMutationArm(arm));
    let channel = measurements.broker_channel_binding([7; 32]).unwrap();
    let claim = digest(9);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, claim, &channel);
    let authorization = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            claim,
            &channel,
        )
        .unwrap();
    let mut handoff = Vec::new();
    CredentialServiceProtocolCodec::encode_writer_broker_handoff(handoff_binding, grant)
        .unwrap()
        .send(|bytes| {
            handoff.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap();
    let writer = match command.action() {
        CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
            let sealed =
                sealed_pair_for_test(&command, claim, &channel, b"secret".to_vec()).unwrap();
            CredentialServiceProtocolCodec::decode_authenticated_writer_broker_handoff(
                &handoff,
                authorization,
                &effects,
                &channel,
                claim,
                sealed.pending,
                sealed.envelope,
            )
            .unwrap()
        }
        CredentialOperationAction::Revoke | CredentialOperationAction::RetiredVersionCleanup => {
            CredentialServiceProtocolCodec::decode_authenticated_writer_control_handoff(
                &handoff,
                authorization,
                &effects,
                &channel,
                claim,
            )
            .unwrap()
        }
        _ => panic!("unsupported service test action"),
    };
    let writer = provider_frame(CredentialServiceRequest::WriterConsume(writer));
    (arm, writer, CredentialMutationGrant::generate().unwrap())
}

pub(in crate::tests) fn arm_frame(
    id: u8,
    sequence: u64,
    key: u8,
    grant: CredentialMutationGrantDigest,
) -> Vec<u8> {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let plan = mutation_plan(
        &store,
        command(id, CredentialOperationAction::Pair),
        super::OWNER,
        sequence,
        id,
        grant,
    );
    runtime_frame(
        key,
        CredentialServiceRequest::RuntimeMutationArm(plan.split().0),
    )
}

pub(in crate::tests) fn arm_frame_for_owner(
    inner_owner: [u8; 32],
    route_owner: [u8; 32],
    sequence: u64,
    key: u8,
) -> Vec<u8> {
    let grant = CredentialMutationGrant::generate().unwrap();
    arm_frame_with_grant_for_owner(inner_owner, route_owner, sequence, key, grant.digest())
}

pub(in crate::tests) fn arm_frame_with_grant_for_owner(
    inner_owner: [u8; 32],
    route_owner: [u8; 32],
    sequence: u64,
    key: u8,
    grant: CredentialMutationGrantDigest,
) -> Vec<u8> {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let plan = mutation_plan(
        &store,
        command(
            u8::try_from(sequence).unwrap(),
            CredentialOperationAction::Pair,
        ),
        inner_owner,
        sequence,
        u8::try_from(sequence).unwrap(),
        grant,
    );
    runtime_frame_for(
        route_owner,
        key,
        CredentialServiceRequest::RuntimeMutationArm(plan.split().0),
    )
}

pub(in crate::tests) fn read_frame(sequence: u64, point: bool, receipt: u8, key: u8) -> Vec<u8> {
    read_frame_at(sequence, point, receipt, key, 10, 20)
}

pub(in crate::tests) fn read_frame_at(
    sequence: u64,
    point: bool,
    receipt: u8,
    key: u8,
    issued: u64,
    expires: u64,
) -> Vec<u8> {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let reads = store.runtime_read_authority();
    let provider = ProviderId::new("provider").unwrap();
    let binding = reads
        .issue_binding(
            CredentialServiceEpoch::from_bytes(EPOCH).unwrap(),
            super::OWNER,
            SESSION,
            12,
            digest(4),
            provider.clone(),
            CredentialVersionRef::new(provider, 1).unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            CredentialServiceRequestSequence::new(sequence).unwrap(),
            CredentialServiceCorrelation::from_bytes([u8::try_from(sequence).unwrap(); 16])
                .unwrap(),
            CredentialServiceDeadline::new(issued, expires).unwrap(),
        )
        .unwrap();
    let request = if point {
        CredentialServiceRequest::PointOfUseRead(
            store
                .dispatch_effect_receipt_authority()
                .issue_point_of_use_read(binding, digest(receipt))
                .unwrap(),
        )
    } else {
        CredentialServiceRequest::MetadataReadback(reads.issue_metadata_readback(binding).unwrap())
    };
    runtime_frame(key, request)
}

fn mutation_plan(
    store: &runne_provider::CredentialEnrollmentStoreAuthority,
    command: CredentialBrokerCommand,
    installation_owner: [u8; 32],
    sequence: u64,
    correlation: u8,
    grant: CredentialMutationGrantDigest,
) -> CredentialRuntimeMutationPlan {
    CredentialRuntimeMutationPlan::issue(
        &store.runtime_arm_authority(),
        command,
        CredentialServiceEpoch::from_bytes(EPOCH).unwrap(),
        installation_owner,
        SESSION,
        12,
        digest(4),
        CredentialServiceRequestSequence::new(sequence).unwrap(),
        CredentialServiceCorrelation::from_bytes([correlation; 16]).unwrap(),
        CredentialServiceDeadline::new(10, 20).unwrap(),
        grant,
    )
    .unwrap()
}

fn command(id: u8, action: CredentialOperationAction) -> CredentialBrokerCommand {
    let provider = ProviderId::new("provider").unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([id; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        action,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

fn runtime_frame(key: u8, request: CredentialServiceRequest) -> Vec<u8> {
    runtime_frame_for(super::OWNER, key, request)
}

fn runtime_frame_for(route_owner: [u8; 32], key: u8, request: CredentialServiceRequest) -> Vec<u8> {
    let inner = provider_frame(request);
    let mut outer = Vec::new();
    auth(key)
        .authenticate_runtime_request(route_owner, &inner)
        .unwrap()
        .send(|bytes| {
            outer.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap();
    outer
}

fn provider_frame(request: CredentialServiceRequest) -> Vec<u8> {
    let mut frame = Vec::new();
    CredentialServiceProtocolCodec::encode_request(request)
        .unwrap()
        .send(|bytes| {
            frame.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap();
    frame
}
