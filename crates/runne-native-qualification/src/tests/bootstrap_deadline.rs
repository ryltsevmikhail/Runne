use crate::{QualificationRunBootstrapError, QualificationRunBootstrapExpectation};

const NOW: u64 = 1_800_000_000;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

fn expectation(
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
    max_run_duration_seconds: u64,
) -> Result<QualificationRunBootstrapExpectation, QualificationRunBootstrapError> {
    QualificationRunBootstrapExpectation::new(
        [0xaa; 32],
        [0xbb; 32],
        [0xcc; 20],
        "run-42",
        [0xdd; 32],
        [0xee; 32],
        [0xff; 32],
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        issued_at,
        expires_at,
        run_not_after,
        max_run_duration_seconds,
    )
}

#[test]
fn bootstrap_expectation_requires_a_safe_bounded_run_deadline() {
    for (issued_at, expires_at, run_not_after, max_run_duration_seconds) in [
        (NOW, NOW + 300, NOW + 3_600, 0),
        (NOW, NOW + 300, NOW + 3_600, u64::MAX),
        (NOW, NOW + 300, NOW + 299, 3_600),
        (NOW, NOW + 300, NOW + 3_601, 3_600),
        (NOW, NOW + 300, u64::MAX, MAX_SAFE_JSON_INTEGER),
        (
            MAX_SAFE_JSON_INTEGER + 1,
            MAX_SAFE_JSON_INTEGER + 2,
            MAX_SAFE_JSON_INTEGER + 3,
            3_600,
        ),
    ] {
        assert!(matches!(
            expectation(
                issued_at,
                expires_at,
                run_not_after,
                max_run_duration_seconds
            ),
            Err(QualificationRunBootstrapError::InvalidExpectation)
        ));
    }
    assert!(expectation(
        MAX_SAFE_JSON_INTEGER - 300,
        MAX_SAFE_JSON_INTEGER,
        MAX_SAFE_JSON_INTEGER,
        300,
    )
    .is_ok());
}
