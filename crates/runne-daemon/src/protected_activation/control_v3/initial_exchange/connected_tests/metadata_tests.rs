use super::*;

#[test]
fn connected_qualified_pair_reaches_begin_without_ticket_or_fence() {
    connected_pair(true, true);
}

#[test]
fn connected_absent_pair_reaches_ordinary_begin() {
    connected_pair(false, true);
}

#[test]
fn connected_fixed_broker_facts_still_reject_authenticated_request() {
    connected_pair(true, false);
}

fn connected_pair(qualified: bool, exact_broker: bool) {
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let rendezvous = crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let fixture = runne_platform_desktop::test_only_connected_ready_v3_enrollment_supervisor();
    let fixture = if exact_broker {
        fixture.with_broker_facts(
            rendezvous.channel_binding(),
            rendezvous.publication_public_key(),
        )
    } else {
        fixture
    };
    let (mut supervisor, peer, keys, owned, installed) = fixture.into_parts();
    let (control, database) = control();
    let verified = Arc::new(AtomicUsize::new(0));
    let daemon = spawn_daemon_with_rendezvous(
        peer,
        keys,
        owned,
        installed,
        control,
        QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        ),
        Arc::clone(&verified),
        crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous::new(
            rendezvous,
        ),
    );
    let begin =
        runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin::new(command(), [9; 32])
            .unwrap();
    let result = supervisor.begin_protected_credential_enrollment_with_qualification(
        begin,
        qualified.then(|| {
            super::super::qualification_admission_tests::support::admission(
                &context_key,
                &fault_key,
            )
        }),
    );
    assert_eq!(
        result.is_ok(),
        exact_broker,
        "only exact broker metadata may reach Begin"
    );
    assert_eq!(
        verified.load(Ordering::SeqCst),
        if qualified { 2 } else { 1 }
    );
    let connection = rusqlite::Connection::open(relay_db(database.path())).unwrap();
    for (table, expected) in [
        ("provider_credential_operations", i64::from(exact_broker)),
        ("provider_credential_ticket_attempts", 0),
        ("provider_qualification_admission_fences", 0),
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, expected, "{table}");
    }
    let cleanup = BoundedThread::spawn(move || supervisor.stop());
    assert_eq!(
        cleanup.wait("qualified supervisor cleanup").unwrap(),
        runne_platform_desktop::BundledRuntimeStopDisposition::Forced
    );
    assert!(daemon.wait("qualified daemon cleanup").is_err());
}
