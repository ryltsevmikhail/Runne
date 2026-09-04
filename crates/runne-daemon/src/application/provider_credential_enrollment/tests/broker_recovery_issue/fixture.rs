use super::*;
pub(super) fn recovery_fixture() -> (Fixture, AcceptedCredentialCleanupRecovery) {
    let f = prepared_cleanup_fixture();
    let head = f.store.lifecycle_snapshot(f.operation.provider()).unwrap();
    let accepted = f
        .store
        .accept_cleanup_recovery(CredentialCleanupRecoveryRequest::new(
            f.operation.operation_id(),
            f.operation.installation_owner_id(),
            f.measurements.release_manifest_digest([9; 32]).unwrap(),
            f.measurements.protected_session_id([17; 32]).unwrap(),
            f.measurements.desktop_supervisor_generation(8).unwrap(),
            7,
            head.lifecycle_revision(),
            head.fence(),
            f.measurements
                .continuation_binding_digest([45; 32])
                .unwrap(),
            30,
        ))
        .unwrap();
    (f, accepted)
}

pub(crate) fn prepared_cleanup_fixture() -> Fixture {
    let mut f = fixture();
    let mut channel = RecordingChannel::default();
    let context = issue_context(&f);
    let receipt = f
        .broker
        .issue_ticket(
            f.operation.clone(),
            f.continuation,
            &context,
            60,
            &f.store,
            &mut channel,
        )
        .unwrap();
    let CredentialBrokerFrame::IssueTicket {
        ticket, binding, ..
    } = CredentialBrokerFrameCodec::decode(&channel.frames[0]).unwrap()
    else {
        panic!()
    };
    let claim = ClaimCredentialOperation::new(
        receipt,
        ticket.binding_digest(),
        f.continuation,
        binding,
        7,
        8,
    )
    .unwrap();
    let claim = f
        .measurements
        .seal_claim_operation(
            claim_measurements_for(&f.measurements, f.continuation, 8),
            claim,
        )
        .unwrap();
    f.store.claim(claim).unwrap();
    let id = f.operation.operation_id();
    f.store
        .mark_native_effect_observed(ObserveNativeEffect::new(
            id,
            CredentialNativeEffectDisposition::PossibleEffect,
        ))
        .unwrap();
    let readback =
        BindCredentialReadback::new(id, CredentialReadbackDisposition::ExactVersion, digest(40))
            .unwrap();
    f.store
        .bind_readback(
            BindCredentialReadback::new(
                id,
                CredentialReadbackDisposition::ExactVersion,
                digest(40),
            )
            .unwrap(),
        )
        .unwrap();
    let version = f.operation.allocated_credential_version().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let readiness = CredentialReadinessObservation::new(
        CredentialOperationId::from_bytes([41; 16]).unwrap(),
        Some(id),
        version.provider().clone(),
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(CredentialBindingDigest::from_measured(*version.ref_digest()).unwrap()),
        digest(9),
        now,
    )
    .unwrap();
    f.store
        .complete(
            CompleteCredentialOperation::new(
                id,
                readback,
                CredentialLifecycleRevision::new(1).unwrap(),
                CredentialFence::new(1).unwrap(),
            )
            .unwrap()
            .with_readiness_observation(readiness),
        )
        .unwrap();
    let revoke = CredentialOperationId::from_bytes([42; 16]).unwrap();
    f.store
        .begin(
            BeginCredentialOperation::new(
                CommandId::from_bytes([43; 16]),
                IdempotencyKey::new("broker-recovery-revoke").unwrap(),
                revoke,
                f.operation.installation_owner_id(),
                version.provider().clone(),
                CredentialOperationAction::Revoke,
                None,
                Some(version.clone()),
                CredentialLifecycleRevision::new(2).unwrap(),
                CredentialFence::new(2).unwrap(),
                digest(44),
                (now + 600) as u64,
            )
            .unwrap()
            .with_qualified_release_tuple(
                f.measurements
                    .issue_qualified_credential_release_tuple(
                        f.measurements.release_manifest_digest([9; 32]).unwrap(),
                    )
                    .unwrap(),
            ),
        )
        .unwrap();
    f.operation = f.store.load_operation(revoke).unwrap();
    f.continuation = digest(45);
    f
}
