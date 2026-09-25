use super::fixture::DurableFixture;
use super::native::poll_absence;
use super::*;

pub(super) fn production_cli() -> std::path::PathBuf {
    let path = std::env::var_os("RUNNE_CLI_BIN")
        .map(std::path::PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_runne").map(std::path::PathBuf::from))
        .unwrap_or_else(|| panic!("set absolute RUNNE_CLI_BIN for daemon unit tests"));
    assert!(
        path.is_absolute() && path.is_file(),
        "production CLI binary must be absolute and exist"
    );
    path
}

struct Started {
    owned: Channel,
    relay: Arc<Mutex<Option<platform::LinuxAuthenticatedPairSecretRelay>>>,
    facts: CredentialMeasurementSnapshot,
    channel_binding: [u8; 32],
}

fn start_writer(fixture: &DurableFixture, binary: &std::path::Path, pair: bool) -> Started {
    let release = fixture
        .operation
        .metadata()
        .qualified_release_tuple_digest()
        .unwrap();
    let image: [u8; 32] = Sha256::digest(std::fs::read(binary).unwrap()).into();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(binary.to_owned(), image, release.as_bytes()).unwrap(),
    );
    let spawned_spec = spec.clone();
    let (daemon, writer) = UnixStream::pair().unwrap();
    daemon
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    daemon
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let channel_binding = [21; 32];
    let authority = DaemonBrokerAuthority::for_test_endpoint(channel_binding, daemon);
    let key = authority.publication_public_key();
    let binding = PendingBrokerRendezvousBinding {
        operation_id: fixture.operation.operation_id(),
        begin_proof: fixture.operation.begin_proof_digest(),
        owner: fixture.operation.installation_owner_id(),
        protected_session: [17; 32],
        tauri_peer: [12; 32],
        daemon_authority: [16; 32],
        database_generation: 7,
        supervisor_generation: 8,
        release_tuple: release,
        expires_at_high_water: 4_000_000_000,
    };
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let (startup_authority, _) = transfer_authority(&issuer, [31; 32], [17; 32]);
    let (handoff_authority, authenticator) = transfer_authority(&issuer, [31; 32], [17; 32]);
    let (sender, receiver) = UnixStream::pair().unwrap();
    let prepared = platform::prepare_daemon_owned_writer_endpoint_handoff(
        receiver,
        &authenticator,
        channel_binding,
        key,
    )
    .unwrap();
    let relay = Arc::new(Mutex::new(None));
    let spawned_relay = relay.clone();
    let spawn = Box::new(move |endpoint, startup| {
        let sender = std::thread::spawn(move || {
            platform::send_daemon_owned_writer_endpoint(
                sender,
                endpoint,
                &handoff_authority,
                channel_binding,
                key,
            )
        });
        let result = if pair {
            platform::spawn_linux_pair_writer_from_prepared_handoff(
                &spawned_spec,
                prepared,
                startup,
                &authenticator,
            )
            .map(|(process, pair_relay)| {
                *spawned_relay.lock().unwrap() = Some(pair_relay);
                process
            })
        } else {
            platform::spawn_linux_writer_from_prepared_handoff(
                &spawned_spec,
                prepared,
                startup,
                &authenticator,
            )
        };
        sender.join().unwrap().unwrap();
        result.map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::Unavailable)
    });
    let channel = launch_linux_writer_with_handshake(
        LinuxWriterLaunchInputs {
            rendezvous: authority,
            control_end_for_writer: writer,
            binding,
            transfer_authority: startup_authority,
            launch_secret: [31; 32],
            daemon_image: Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap())
                .into(),
        },
        &spec,
        spawn,
    )
    .unwrap();
    let facts = live_measurements(fixture, &channel);
    Started {
        owned: Channel(Some(channel)),
        relay,
        facts,
        channel_binding,
    }
}

fn live_measurements(
    f: &DurableFixture,
    channel: &LinuxCredentialBrokerChannel,
) -> CredentialMeasurementSnapshot {
    let (start, image, handle) = channel.claim_process_facts().unwrap();
    let a = &f.measurements;
    CredentialMeasurementSnapshot::new(
        a.candidate_source_identity([10; 32]).unwrap(),
        a.release_manifest_digest([9; 32]).unwrap(),
        a.desktop_executable_identity([12; 32]).unwrap(),
        a.writer_executable_identity(image).unwrap(),
        a.reader_executable_identity(
            Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap()).into(),
        )
        .unwrap(),
        a.contract_bundle_digest([15; 32]).unwrap(),
        a.daemon_authority_id([16; 32]).unwrap(),
        a.protected_session_id([17; 32]).unwrap(),
        a.desktop_supervisor_generation(8).unwrap(),
        a.writer_launch_id([18; 32]).unwrap(),
        a.writer_process_start_identity(start).unwrap(),
        a.writer_process_handle_identity(handle).unwrap(),
        a.broker_channel_binding([21; 32]).unwrap(),
        a.continuation_binding_digest(f.continuation.as_bytes())
            .unwrap(),
    )
    .unwrap()
}

pub(super) fn pair_through_real_writer(f: &mut DurableFixture, binary: &std::path::Path) {
    let mut started = start_writer(f, binary, true);
    let channel = started.owned.0.as_mut().unwrap();
    let context = f
        .broker
        .claim_issue_context(
            started.facts.clone(),
            started.channel_binding,
            f.continuation,
            7,
            8,
        )
        .unwrap();
    let receipt = f
        .broker
        .issue_ticket(
            f.operation.clone(),
            f.continuation,
            &context,
            60,
            f.store(),
            channel,
        )
        .unwrap();
    let mut claimed = f
        .broker
        .claim_ticket_from_channel(
            receipt,
            f.continuation,
            7,
            8,
            started.facts,
            f.store(),
            channel,
        )
        .unwrap();
    let relay_frame = claimed.take_secret_relay().unwrap().unwrap();
    started
        .relay
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .seal_and_write(
            &relay_frame,
            zeroize::Zeroizing::new(b"d1.1b-disposable-pair-seed".to_vec()),
        )
        .unwrap();
    f.broker
        .release_claimed_effect_to_channel(&claimed, channel)
        .unwrap();
    let observed = f
        .broker
        .observe_effect_from_channel(claimed, f.store(), channel)
        .unwrap();
    assert_eq!(
        observed.state(),
        CredentialOperationState::NativeEffectObserved
    );
    drop(started.owned);
    reconcile_native(f, binary, unix_now());
    assert_eq!(
        f.store()
            .load_operation(observed.operation_id())
            .unwrap()
            .state(),
        CredentialOperationState::Completed
    );
}

pub(super) fn revoke_through_real_writer_without_reading_ack(
    f: &mut DurableFixture,
    binary: &std::path::Path,
    service: &str,
) {
    let mut started = start_writer(f, binary, false);
    let channel = started.owned.0.as_mut().unwrap();
    let head = f
        .store()
        .lifecycle_snapshot(f.operation.provider())
        .unwrap();
    let accepted = f
        .store()
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
            60,
        ))
        .unwrap();
    let context = f
        .broker
        .claim_issue_context(
            started.facts.clone(),
            started.channel_binding,
            f.continuation,
            7,
            8,
        )
        .unwrap();
    let receipt = f
        .broker
        .issue_ticket(accepted, f.continuation, &context, 60, f.store(), channel)
        .unwrap();
    let mut claimed = f
        .broker
        .claim_ticket_from_channel(
            receipt,
            f.continuation,
            7,
            8,
            started.facts,
            f.store(),
            channel,
        )
        .unwrap();
    assert!(claimed.take_secret_relay().unwrap().is_none());
    f.broker
        .release_control_only_effect(&claimed, f.operation.operation_id(), f.store(), channel)
        .unwrap();
    poll_absence(service);
    // We intentionally never call observe_effect_from_channel: the writer's
    // terminal frame remains unread while the retained child is terminated.
    drop(started.owned);
}
