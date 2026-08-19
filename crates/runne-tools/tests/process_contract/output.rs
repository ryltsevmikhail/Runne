use runne_tools::{
    ProcessCancellationDispositionV1, ProcessContractErrorV1, ProcessOutputBoundsV1,
};

#[test]
fn stdio_bounds_allow_closed_stdin_and_reject_nonempty_input() {
    assert_eq!(
        ProcessOutputBoundsV1::new(0, 4, 4, 4),
        Ok(ProcessOutputBoundsV1::new(0, 4, 4, 4).expect("closed stdin bounds"))
    );
    assert_eq!(
        ProcessOutputBoundsV1::new(1, 4, 4, 8),
        Err(ProcessContractErrorV1::InputBoundsExceeded)
    );
    assert_eq!(
        ProcessOutputBoundsV1::new(0, 4, 4, 9),
        Err(ProcessContractErrorV1::InputBoundsExceeded)
    );

    let bounds = ProcessOutputBoundsV1::new(0, 4, 5, 6).expect("coherent bounds");
    assert_eq!(bounds.validate_stdin(b""), Ok(()));
    assert_eq!(
        bounds.validate_stdin(b"four"),
        Err(ProcessContractErrorV1::InputBoundsExceeded)
    );
    assert_eq!(
        bounds.cancel_for_stdin(b"four"),
        ProcessCancellationDispositionV1::PolicyRejected
    );
}
