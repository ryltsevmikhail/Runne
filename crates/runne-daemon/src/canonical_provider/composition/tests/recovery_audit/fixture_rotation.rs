impl Harness {
    pub(super) fn rotate_openai_fixture_credential(&self) -> (String, String) {
        use runne_domain::id::{CommandId, IdempotencyKey};
        use runne_provider::{
            AttachCredentialProcess, BeginCredentialOperation, BindCredentialReadback,
            ClaimCredentialOperation, CompleteCredentialOperation, CredentialAuthorityPair,
            CredentialBindingDigest, CredentialEnrollmentAuthorityPair,
            CredentialInstallationOwnerId,
            CredentialNativeEffectDisposition, CredentialOperationAction,
            CredentialOperationId, CredentialReadbackDisposition,
            CredentialReadinessDisposition, CredentialReadinessObservation,
            CredentialVersionRef,
            IssueCredentialTicketDigest, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
            ProviderId,
        };
        use runne_store::provider::SqliteProviderCredentialLifecycleStore;

        let provider = ProviderId::new("openai").expect("fixture provider");
        let owner = CredentialInstallationOwnerId::from_bytes([0xD3; 32])
            .expect("fixture installation owner");
        let (lifecycle_authority, _) = CredentialAuthorityPair::new().split();
        let (store_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
            self.writer_connection(),
            lifecycle_authority,
            store_authority,
        )
        .expect("online enrollment store");
        let before = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider)
            .expect("current online credential head");
        let version = CredentialVersionRef::new(provider.clone(), before.next_credential_version())
            .expect("next credential version");
        let operation = CredentialOperationId::from_bytes(*uuid::Uuid::now_v7().as_bytes())
            .expect("replacement operation id");
        let process = measured(0x32);
        let request = measured(0x33);
        let desktop = measured(0x34);
        let release = measurements
            .issue_qualified_credential_release_tuple(
                measurements
                    .release_manifest_digest([0x35; 32])
                    .expect("fixture release manifest"),
            )
            .expect("qualified fixture release");
        let release_digest = release.digest();
        let now = chrono::Utc::now().timestamp();
        let begin = BeginCredentialOperation::new(
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            IdempotencyKey::new("x2-recovery-fixture-openai-rotation")
                .expect("rotation idempotency key"),
            operation,
            owner,
            provider.clone(),
            CredentialOperationAction::Pair,
            Some(version.clone()),
            None,
            before.lifecycle_revision(),
            before.fence(),
            request,
            u64::try_from(now + 600).expect("bounded ticket lifetime"),
        )
        .expect("replacement operation")
        .with_qualified_release_tuple(release);
        ProviderCredentialEnrollmentStore::begin(&store, begin)
            .expect("begin online replacement");
        ProviderCredentialEnrollmentStore::attach_process(
            &store,
            AttachCredentialProcess::new(operation, process).expect("attached process"),
        )
        .expect("attach replacement process");
        let ticket = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
            &store,
            IssueCredentialTicketDigest::new(operation, request, process, 600)
                .expect("replacement ticket"),
        )
        .expect("issue replacement ticket");
        let draft = ClaimCredentialOperation::new(ticket, request, process, desktop, 1, 1)
            .expect("replacement claim");
        let snapshot = credential_measurements(&measurements, &draft);
        let binding = measurements
            .measure_claim_operation(&snapshot, &draft)
            .expect("measured replacement claim");
        let claim = measurements
            .seal_claim_operation(
                snapshot,
                draft
                    .bind_process_release_digest(binding)
                    .expect("replacement process release"),
            )
            .expect("sealed replacement claim");
        ProviderCredentialEnrollmentStore::claim(&store, claim).expect("claim replacement");
        let replacement_readback = || {
            BindCredentialReadback::new(
                operation,
                CredentialReadbackDisposition::ExactVersion,
                measured(0x36),
            )
            .expect("exact replacement readback")
        };
        ProviderCredentialEnrollmentStore::mark_native_effect_observed(
            &store,
            ObserveNativeEffect::new(operation, CredentialNativeEffectDisposition::PossibleEffect),
        )
        .expect("record replacement effect");
        ProviderCredentialEnrollmentStore::bind_readback(&store, replacement_readback())
            .expect("bind exact replacement version");
        let ready = CredentialReadinessObservation::new(
            CredentialOperationId::from_bytes(*uuid::Uuid::now_v7().as_bytes())
                .expect("replacement readiness id"),
            Some(operation),
            provider.clone(),
            increment(before.lifecycle_revision()),
            increment_readiness(before.readiness_revision()),
            CredentialReadinessDisposition::Ready,
            Some(CredentialBindingDigest::from_measured(*version.ref_digest()).unwrap()),
            release_digest,
            chrono::Utc::now().timestamp(),
        )
        .expect("replacement readiness");
        ProviderCredentialEnrollmentStore::complete(
            &store,
            CompleteCredentialOperation::new(
                operation,
                replacement_readback(),
                before.lifecycle_revision(),
                before.fence(),
            )
            .expect("complete replacement")
            .with_readiness_observation(ready),
        )
        .expect("commit replacement");

        let cleanup = ProviderCredentialEnrollmentStore::prepared_cleanup_operations(
            &store, owner, &provider,
        )
        .expect("prepared retired cleanup")
        .into_iter()
        .next()
        .expect("retired version cleanup created by replacement");
        let cleanup_id = cleanup.operation_id();
        let cleanup_process = measured(0x37);
        let cleanup_request = measured(0x38);
        ProviderCredentialEnrollmentStore::attach_process(
            &store,
            AttachCredentialProcess::new(cleanup_id, cleanup_process)
                .expect("cleanup process"),
        )
        .expect("attach cleanup process");
        let cleanup_ticket = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
            &store,
            IssueCredentialTicketDigest::new(cleanup_id, cleanup_request, cleanup_process, 600)
                .expect("cleanup ticket"),
        )
        .expect("issue cleanup ticket");
        let cleanup_draft = ClaimCredentialOperation::new(
            cleanup_ticket,
            cleanup_request,
            cleanup_process,
            measured(0x39),
            1,
            1,
        )
        .expect("cleanup claim");
        let cleanup_snapshot = credential_measurements(&measurements, &cleanup_draft);
        let cleanup_binding = measurements
            .measure_claim_operation(&cleanup_snapshot, &cleanup_draft)
            .expect("measured cleanup claim");
        let cleanup_claim = measurements
            .seal_claim_operation(
                cleanup_snapshot,
                cleanup_draft
                    .bind_process_release_digest(cleanup_binding)
                    .expect("cleanup process release"),
            )
            .expect("sealed cleanup claim");
        ProviderCredentialEnrollmentStore::claim(&store, cleanup_claim)
            .expect("claim retired cleanup");
        let absence = || {
            BindCredentialReadback::new(
                cleanup_id,
                CredentialReadbackDisposition::ExactAbsence,
                measured(0x3A),
            )
            .expect("exact retired credential absence")
        };
        ProviderCredentialEnrollmentStore::mark_native_effect_observed(
            &store,
            ObserveNativeEffect::new(
                cleanup_id,
                CredentialNativeEffectDisposition::PossibleEffect,
            ),
        )
        .expect("record retired cleanup effect");
        ProviderCredentialEnrollmentStore::bind_readback(&store, absence())
            .expect("bind exact retired absence");
        let head = ProviderCredentialEnrollmentStore::lifecycle_snapshot(&store, &provider)
            .expect("replacement lifecycle head");
        let cleanup_ready = CredentialReadinessObservation::new(
            CredentialOperationId::from_bytes(*uuid::Uuid::now_v7().as_bytes())
                .expect("cleanup readiness id"),
            Some(cleanup_id),
            provider,
            increment(head.lifecycle_revision()),
            increment_readiness(head.readiness_revision()),
            CredentialReadinessDisposition::Ready,
            Some(CredentialBindingDigest::from_measured(*version.ref_digest()).unwrap()),
            release_digest,
            chrono::Utc::now().timestamp(),
        )
        .expect("cleanup readiness");
        ProviderCredentialEnrollmentStore::complete(
            &store,
            CompleteCredentialOperation::new(
                cleanup_id,
                absence(),
                head.lifecycle_revision(),
                head.fence(),
            )
            .expect("complete retired cleanup")
            .with_readiness_observation(cleanup_ready),
        )
        .expect("commit exact retired cleanup");
        (
            format!("X'{}'", hex::encode_upper(operation.as_bytes())),
            format!("X'{}'", hex::encode_upper(cleanup_id.as_bytes())),
        )
    }
}

fn measured(value: u8) -> runne_provider::CredentialBindingDigest {
    runne_provider::CredentialBindingDigest::from_measured([value; 32])
        .expect("nonzero fixture measurement")
}

fn increment(value: runne_provider::CredentialLifecycleRevision) -> runne_provider::CredentialLifecycleRevision {
    runne_provider::CredentialLifecycleRevision::new(value.get() + 1).expect("revision increment")
}

fn increment_readiness(value: runne_provider::CredentialReadinessRevision) -> runne_provider::CredentialReadinessRevision {
    runne_provider::CredentialReadinessRevision::new(value.get() + 1).expect("readiness increment")
}

fn credential_measurements(
    authority: &runne_provider::CredentialEnrollmentMeasurementAuthority,
    claim: &runne_provider::ClaimCredentialOperation,
) -> runne_provider::CredentialMeasurementSnapshot {
    runne_provider::CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([0xE1; 32]).unwrap(),
        authority.release_manifest_digest([0xE2; 32]).unwrap(),
        authority.desktop_executable_identity([0xE3; 32]).unwrap(),
        authority.writer_executable_identity([0xE4; 32]).unwrap(),
        authority.reader_executable_identity([0xE5; 32]).unwrap(),
        authority.contract_bundle_digest([0xE6; 32]).unwrap(),
        authority.daemon_authority_id([0xE7; 32]).unwrap(),
        authority.protected_session_id([0xE8; 32]).unwrap(),
        authority.desktop_supervisor_generation(claim.desktop_supervisor_generation()).unwrap(),
        authority.writer_launch_id([0xE9; 32]).unwrap(),
        authority.writer_process_start_identity([0xEA; 32]).unwrap(),
        authority.writer_process_handle_identity([0xEB; 32]).unwrap(),
        authority.broker_channel_binding([0xEC; 32]).unwrap(),
        authority.continuation_binding_digest(claim.continuation_binding_digest().as_bytes()).unwrap(),
    )
    .expect("closed credential claim measurements")
}
