#[test]
fn capacity_rejection_commits_clock_before_regressed_consume_and_preallocate() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("capacity-clock.sqlite");
    let initial = store(&path);
    let first = initial.preallocate(input(0, 100)).unwrap();
    for key in 1..32_u8 {
        initial.preallocate(input(key, 100)).unwrap();
    }

    assert!(matches!(
        initial.preallocate(input(32, 120)),
        Err(BootstrapReservationError::Capacity),
    ));
    drop(initial);

    assert_eq!(clock(&path), 120);
    let reopened = store(&path);
    assert!(matches!(
        reopened.preallocate(input(32, 110)),
        Err(BootstrapReservationError::ClockRegression),
    ));
    let accept = |_: &_| true;
    assert!(matches!(
        reopened.consume_final(ConsumeReservation {
            challenge_id: first.challenge_id,
            binding_proof: [2; 32],
            authority_digest: [7; 32],
            observed_at_unix_microseconds: 110,
            verify: &accept,
        }),
        Err(BootstrapReservationError::ClockRegression),
    ));
    drop(reopened);

    assert_eq!(row_count(&path, "bootstrap_reservations"), 32);
    assert_eq!(row_count(&path, "bootstrap_reservation_tombstones"), 0);
}
