use super::*;
use runne_api::RunBinding;

fn binding(changed: usize) -> RunBinding {
    let hash = |field| if changed == field { [9; 32] } else { [1; 32] };
    RunBinding::new(
        if changed == 0 {
            "another-run"
        } else {
            "run-42"
        },
        if changed == 1 { [9; 20] } else { [1; 20] },
        hash(2),
        hash(3),
        hash(4),
        hash(5),
        hash(6),
    )
    .unwrap()
}

fn offer() -> DesktopOffer {
    DesktopOffer::new([2; 32], [3; 32], binding(usize::MAX), 110, 200).unwrap()
}

fn ack(changed: usize) -> BootstrapAck {
    BootstrapAck::new(
        if changed == 7 { [9; 32] } else { [3; 32] },
        if changed == 8 { [9; 32] } else { [4; 32] },
        binding(changed),
        [5; 32],
        if changed == 9 { 201 } else { 200 },
    )
    .unwrap()
}

#[test]
fn acknowledgement_requires_every_retained_binding_and_challenge() {
    assert!(matches_acknowledgement(&offer(), &ack(usize::MAX), [4; 32]));
    for changed in 0..10 {
        assert!(
            !matches_acknowledgement(&offer(), &ack(changed), [4; 32]),
            "field {changed}"
        );
    }
}

#[test]
fn activation_budget_never_extends_an_inherited_deadline_or_clock_rollback() {
    let inherited = Instant::now() + Duration::from_secs(5);
    let first = offer_deadline(&offer(), 100, inherited, Instant::now()).unwrap();
    assert_eq!(first, inherited);
    assert_eq!(
        offer_deadline(&offer(), 90, first, Instant::now()).unwrap(),
        first
    );
    assert!(offer_deadline(&offer(), 110, inherited, Instant::now()).is_none());
    assert!(offer_deadline(&offer(), 100, Instant::now(), Instant::now()).is_none());
}

#[test]
fn long_offer_is_capped_to_the_protected_activation_window() {
    let before = Instant::now();
    let long = DesktopOffer::new([2; 32], [3; 32], binding(usize::MAX), 1000, 2000).unwrap();
    let deadline = offer_deadline(&long, 100, before + Duration::from_mins(15), before).unwrap();
    assert!(deadline <= Instant::now() + ACTIVATION_LIMIT);
    assert!(deadline >= before + ACTIVATION_LIMIT);
    assert!(
        deadline.checked_sub(FIRST_ACTIVATION_RESERVE).unwrap()
            <= Instant::now() + Duration::from_secs(20)
    );
}

#[test]
fn delayed_wall_sample_does_not_restart_the_activation_clock() {
    let now = Instant::now();
    let sampled_at = now
        .checked_sub(Duration::from_secs(31))
        .expect("test runtime has at least 31 seconds of monotonic uptime");
    let long = DesktopOffer::new([2; 32], [3; 32], binding(usize::MAX), 1000, 2000).unwrap();
    assert!(offer_deadline(&long, 100, now + Duration::from_secs(30), sampled_at).is_none());
}
