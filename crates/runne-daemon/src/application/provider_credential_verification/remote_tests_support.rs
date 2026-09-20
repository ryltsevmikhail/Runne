fn verify_once(
    control: Arc<DaemonProviderCredentialEnrollmentControl>,
    release: CredentialBindingDigest,
    suffix: u8,
) -> impl std::future::Future<
    Output = Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError>,
> {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let command = VerifyProviderCredential::new(
        ProviderCredentialProviderV2::KimiCoding,
        2,
        ProviderCredentialVerificationKindV2::Remote,
        format!("00000000-0000-7000-8000-00000000000{suffix}"),
        format!("native-{suffix}"),
    )
    .unwrap();
    let context = ProviderCredentialCommandContext {
        command_id: CommandId::parse(command.command_identity()).unwrap(),
        idempotency_key: IdempotencyKey::new(command.command_identity()).unwrap(),
        principal: ApiPrincipalId::new("protected-desktop-owner").unwrap(),
        actor: ApiActor::new("runne-tauri-native-host").unwrap(),
    };
    let binding = ProviderCredentialVerifyIntentBinding::new(&command, &context);
    let authority = issuer
        .issue_base([1; 32], release.as_bytes(), [3; 32], 8, [4; 32], 1, [5; 32])
        .unwrap();
    let proof = issuer
        .issue_intent_proof(
            [5 + suffix; 32],
            *authority.protected_session_id(),
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    async move {
        tokio::task::spawn_blocking(move || {
            control.verify_admitted(verifier, authority, proof, context, command)
        })
        .await
        .unwrap()
    }
}

fn ready_store() -> (
    Arc<runne_store::provider::SqliteProviderCredentialLifecycleStore>,
    CredentialEnrollmentMeasurementAuthority,
    CredentialBindingDigest,
    CredentialEnrollmentStoreAuthority,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.keep().join("remote-verification.sqlite");
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (store_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = Arc::new(
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &path,
            lifecycle,
            store_authority.clone(),
        )
        .unwrap(),
    );
    let provider = ProviderId::new("kimi-coding").unwrap();
    let head =
        ProviderCredentialEnrollmentStore::begin_admission_snapshot(&*store, &provider).unwrap();
    let active =
        CredentialVersionRef::new(provider.clone(), head.next_credential_version()).unwrap();
    let release_tuple = measurements
        .issue_qualified_credential_release_tuple(
            measurements.release_manifest_digest([0x40; 32]).unwrap(),
        )
        .unwrap();
    let release = release_tuple.digest();
    let operation = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let begin = BeginCredentialOperation::new(
        CommandId::from_bytes([2; 16]),
        IdempotencyKey::new("seed-remote").unwrap(),
        operation,
        CredentialInstallationOwnerId::from_bytes([0x30; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(active.clone()),
        None,
        head.lifecycle_revision(),
        head.fence(),
        digest(0x41),
        4_000_000_000,
    )
    .unwrap()
    .with_qualified_release_tuple(release_tuple);
    ProviderCredentialEnrollmentStore::begin(&*store, begin).unwrap();
    let continuation = digest(0x42);
    ProviderCredentialEnrollmentStore::attach_process(
        &*store,
        AttachCredentialProcess::new(operation, continuation).unwrap(),
    )
    .unwrap();
    let ticket_digest = digest(0x43);
    let ticket = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
        &*store,
        IssueCredentialTicketDigest::new(operation, ticket_digest, continuation, 300).unwrap(),
    )
    .unwrap();
    let draft =
        ClaimCredentialOperation::new(ticket, ticket_digest, continuation, digest(0x44), 1, 1)
            .unwrap();
    let measured = measurement_snapshot(&measurements, &draft);
    let claim_binding = measurements
        .measure_claim_operation(&measured, &draft)
        .unwrap();
    let bound = draft.bind_process_release_digest(claim_binding).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &*store,
        measurements.seal_claim_operation(measured, bound).unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &*store,
        ObserveNativeEffect::new(operation, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        &*store,
        BindCredentialReadback::new(
            operation,
            CredentialReadbackDisposition::ExactVersion,
            digest(0x45),
        )
        .unwrap(),
    )
    .unwrap();
    let readiness = CredentialReadinessObservation::new(
        CredentialOperationId::from_bytes([3; 16]).unwrap(),
        Some(operation),
        provider,
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(CredentialBindingDigest::from_measured(*active.ref_digest()).unwrap()),
        release,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::complete(
        &*store,
        runne_provider::CompleteCredentialOperation::new(
            operation,
            BindCredentialReadback::new(
                operation,
                CredentialReadbackDisposition::ExactVersion,
                digest(0x45),
            )
            .unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            runne_provider::CredentialFence::new(1).unwrap(),
        )
        .unwrap()
        .with_readiness_observation(readiness),
    )
    .unwrap();
    seed_local_verification(&store);
    (store, measurements, release, store_authority)
}

fn seed_local_verification(store: &SqliteProviderCredentialLifecycleStore) {
    let provider = ProviderId::new("kimi-coding").unwrap();
    let current =
        ProviderCredentialEnrollmentStore::current_verification_context(store, &provider).unwrap();
    // The insert contract pins every verification on the current readiness to
    // started_at == head high-water, so the later remote verification ties this
    // seed and safe_projection decides by `observation_id DESC`. The minimal
    // non-zero id (from_bytes rejects all-zero) loses every byte comparison
    // except an exactly equal random draw, which the store rejects earlier as
    // a duplicate observation.
    let observation = CredentialOperationId::from_bytes([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ])
    .unwrap();
    let lease = ProviderCredentialEnrollmentStore::begin_verification(
        store,
        BeginCredentialVerification::new(
            observation,
            None,
            provider,
            CredentialVerificationKind::Local,
            current.lifecycle_revision(),
            current.fence(),
            current.readiness_revision(),
            current.release_tuple_digest(),
            digest(0x46),
            CredentialVerifierRevision::new(1).unwrap(),
            current.observed_at_high_water(),
            4_000_000_000,
        )
        .unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::complete_verification(
        store,
        CompleteCredentialVerification::new(
            CredentialVerificationObservation::new(
                lease.observation_id(),
                CredentialVerificationResult::Verified,
                current.observed_at_high_water(),
            )
            .unwrap(),
            current.lifecycle_revision(),
            current.fence(),
        ),
    )
    .unwrap();
}

fn measurement_snapshot(
    authority: &CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
) -> runne_provider::CredentialMeasurementSnapshot {
    runne_provider::CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([0x50; 32]).unwrap(),
        authority.release_manifest_digest([0x51; 32]).unwrap(),
        authority.desktop_executable_identity([0x52; 32]).unwrap(),
        authority.writer_executable_identity([0x53; 32]).unwrap(),
        authority.reader_executable_identity([0x54; 32]).unwrap(),
        authority.contract_bundle_digest([0x55; 32]).unwrap(),
        authority.daemon_authority_id([0x56; 32]).unwrap(),
        authority.protected_session_id([0x57; 32]).unwrap(),
        authority
            .desktop_supervisor_generation(claim.desktop_supervisor_generation())
            .unwrap(),
        authority.writer_launch_id([0x58; 32]).unwrap(),
        authority.writer_process_start_identity([0x59; 32]).unwrap(),
        authority
            .writer_process_handle_identity([0x5a; 32])
            .unwrap(),
        authority.broker_channel_binding([0x5b; 32]).unwrap(),
        authority
            .continuation_binding_digest(claim.continuation_binding_digest().as_bytes())
            .unwrap(),
    )
    .unwrap()
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
