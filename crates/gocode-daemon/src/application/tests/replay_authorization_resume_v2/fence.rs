#[test]
fn v2_precommit_fences_concurrent_revocation_through_commit() {
    let binding = replay_binding();
    let authority_secret = [0x88; 32];
    let mut local_session = LocalSessionService::new(binding.clone(), authority_secret);
    local_session.set_sensitivity_ceiling(Sensitivity::Sensitive);
    let challenge = local_session
        .issue_challenge([0x11; 32], [0x12; 32], Duration::ZERO)
        .unwrap();
    let mut proof = HmacSha256::new_from_slice(&authority_secret).unwrap();
    proof.update(&bootstrap_proof_transcript(
        &binding, [0x12; 32], [0x11; 32],
    ));
    local_session
        .authenticate(
            challenge.id,
            BootstrapProof::new(proof.finalize().into_bytes().into()),
            [0x13; 32],
            Duration::ZERO,
        )
        .unwrap();
    let issuer = local_session
        .authorize_wire_with_replay_issuer(&[0x13; 32], Duration::ZERO)
        .unwrap()
        .1;
    let context = local_session.replay_resume_context_v2(&issuer).unwrap();
    let local_session = Arc::new(Mutex::new(local_session));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let connection = Connection::open_in_memory().unwrap();
    gocode_store::schema::apply_migrations(&connection).unwrap();
    let store = Arc::new(TransactionalAdmissionStore {
        connection: Mutex::new(connection),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let service = ReplayService::new(
        store.clone(),
        [0x14; 32],
        *binding.stable().lineage_id(),
        Arc::new(DaemonReplayAuthorization::new(
            *binding.stable().authority_id(),
            Arc::clone(&local_session),
        )),
    );
    let wire = v2_resume_wire(&binding, [0x13; 32]);
    let scope = ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: *binding.stable().authority_id(),
    };
    gocode_api::validate_unauthenticated_replay_retention_baseline_v2(
        &wire,
        ApiReplayAggregateKind::TaskRun,
        binding.stable().authority_id(),
    )
    .unwrap();
    let (admission_tx, admission_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(service.resume_from_retention_baseline_v2(
            "local-owner",
            7,
            binding.stable().authority_id(),
            3,
            &scope,
            &wire,
            context,
            Arc::new(AllowDelivery),
        ));
        let _ = admission_tx.send(result);
    });
    entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("precommit must reach transaction readback without recursive locking");
    let (revoked_tx, revoked_rx) = std::sync::mpsc::channel();
    let (revoker_started_tx, revoker_started_rx) = std::sync::mpsc::channel();
    let revoker_session = Arc::clone(&local_session);
    std::thread::spawn(move || {
        revoker_started_tx.send(()).unwrap();
        revoker_session.lock().unwrap().set_authorization_epoch(4);
        revoked_tx.send(()).unwrap();
    });
    revoker_started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("revoker must reach the authority fence");
    assert!(
        revoked_rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "revocation must not pass the V2 precommit fence before commit"
    );
    release_tx.send(()).unwrap();
    let (session, events, _cursor, _accepted) = admission_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("admission must complete after releasing the transaction")
        .unwrap();
    assert!(events.is_empty());
    assert_eq!(session.authorization_epoch, 3);
    revoked_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("revocation must finish after commit");
    assert_eq!(store.stored_epoch(&session.session_id), 3);
}
