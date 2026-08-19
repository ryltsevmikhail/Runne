use runne_security::process_contract::{
    BoundedArgvV1, InputBoundsV1, PortableUtf8V1, ProcessContractError, ProcessIoBoundsV1,
};

use super::support::text;

#[test]
fn portable_utf8_rejects_invalid_utf8_and_nul() {
    assert_eq!(
        PortableUtf8V1::from_bytes(vec![0xff]),
        Err(ProcessContractError::IntentMalformed)
    );
    assert_eq!(
        PortableUtf8V1::from_bytes(b"contains\0nul".to_vec()),
        Err(ProcessContractError::IntentMalformed)
    );
}

#[test]
fn argv_enforces_count_per_argument_and_total_bounds() {
    assert_eq!(
        BoundedArgvV1::new(
            vec![text("one"), text("two")],
            InputBoundsV1::new(1, 3, 6).expect("valid bounds"),
        ),
        Err(ProcessContractError::InputBoundsExceeded)
    );
    assert_eq!(
        BoundedArgvV1::new(
            vec![text("four")],
            InputBoundsV1::new(1, 3, 4).expect("valid bounds"),
        ),
        Err(ProcessContractError::InputBoundsExceeded)
    );
    assert_eq!(
        BoundedArgvV1::new(
            vec![text("three"), text("two")],
            InputBoundsV1::new(2, 5, 4).expect("valid bounds"),
        ),
        Err(ProcessContractError::InputBoundsExceeded)
    );
}

#[test]
fn process_io_bounds_accept_combined_within_stream_capacity() {
    assert_eq!(
        ProcessIoBoundsV1::new(16, 16, 16, 1, false),
        Ok(ProcessIoBoundsV1::new(16, 16, 16, 1, false).expect("valid bounds"))
    );
}

#[test]
fn process_io_bounds_rejects_combined_above_stream_capacity() {
    assert_eq!(
        ProcessIoBoundsV1::new(16, 16, 33, 1, false),
        Err(ProcessContractError::InputBoundsExceeded)
    );
}

#[test]
fn process_io_bounds_rejects_zero_combined_or_timeout_and_overflow() {
    assert_eq!(
        ProcessIoBoundsV1::new(16, 16, 0, 1, false),
        Err(ProcessContractError::InputBoundsExceeded)
    );
    assert_eq!(
        ProcessIoBoundsV1::new(16, 16, 16, 0, false),
        Err(ProcessContractError::InputBoundsExceeded)
    );
    assert_eq!(
        ProcessIoBoundsV1::new(u64::MAX, 1, 1, 1, false),
        Err(ProcessContractError::InputBoundsExceeded)
    );
}
