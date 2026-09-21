// NM-10 §C-E provider sink scan: the runtime terminal/outbox boundary driven
// with the S7-registered fake env secrets through the production
// `SecretBroker` guard, plus frozen-rule scans over the durable state.
#[tokio::test(flavor = "current_thread")]
async fn nm10_registered_secret_never_reaches_terminal_outbox() {
    let mut broker = runne_security::SecretBroker::new();
    broker
        .register(
            "RUNNE_T1_FAKE_SECRET_ENV",
            nm10_rules::FAKE_SECRET_ENV.as_bytes().to_vec(),
        )
        .expect("register FAKE-SECRET-003");
    broker
        .register(
            "RUNNE_T1_FAKE_CRASH_REPORT_VAR",
            nm10_rules::FAKE_SECRET_CRASH.as_bytes().to_vec(),
        )
        .expect("register FAKE-SECRET-006");
    let guard = broker.prohibited_content_guard();

    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &guard,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(&runtime, &fixture, successful_events(nm10_rules::FAKE_SECRET_ENV)).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Err(RuntimeProviderExecutionError::PolicyDenied),
        "registered secret must be denied at the terminal boundary"
    );
    let connection = validated_connection(&fixture);
    for table in [
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "policy denial mutated {table}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn nm10_clean_terminal_flow_scans_free_of_frozen_canaries() {
    let mut broker = runne_security::SecretBroker::new();
    broker
        .register(
            "RUNNE_T1_FAKE_SECRET_ENV",
            nm10_rules::FAKE_SECRET_ENV.as_bytes().to_vec(),
        )
        .expect("register FAKE-SECRET-003");
    broker
        .register(
            "RUNNE_T1_FAKE_CRASH_REPORT_VAR",
            nm10_rules::FAKE_SECRET_CRASH.as_bytes().to_vec(),
        )
        .expect("register FAKE-SECRET-006");
    let guard = broker.prohibited_content_guard();

    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &FIXED_PRICING,
        &guard,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    const CLEAN: &str = "clean terminal output for the nm10 sink scan";
    poll_events(&runtime, &fixture, successful_events(CLEAN)).await;
    runtime
        .finalize_terminal_output(&context(&fixture))
        .expect("clean terminal output settles");

    // Frozen-rule scan over the durable database bytes: neither the
    // registered secrets nor the harness canary appears in the clean flow.
    let path = fixture.database_path().to_path_buf();
    let bytes = std::fs::read(&path).expect("database bytes");
    let scanner = nm10_rules::scanner(&[
        nm10_rules::FAKE_SECRET_ENV,
        nm10_rules::FAKE_SECRET_CRASH,
        nm10_rules::CANARY,
    ]);
    nm10_rules::scan_absent(&scanner, "sink:provider-execution-db", &bytes);
    // Scanner liveness against the same patterns.
    let live = format!("x{}y", nm10_rules::FAKE_SECRET_ENV);
    let live_match = match scanner.scan_reader(live.as_bytes()) {
        Ok(found) => found,
        Err(_) => panic!("live scan failed"),
    };
    assert!(live_match.is_some());
}
