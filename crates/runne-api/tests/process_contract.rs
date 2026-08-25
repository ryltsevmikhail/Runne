use runne_api::{
    MAX_PROCESS_OUTPUT_BYTES, MAX_PROCESS_OUTPUT_CHUNKS, MAX_PROCESS_OUTPUT_WIRE_BYTES,
    ProcessOutputChunk, ProcessOutputPage, ProcessOutputStream,
};

#[test]
fn process_output_rejects_terminal_control_and_oversized_text() {
    assert_eq!(
        ProcessOutputChunk::new(1, ProcessOutputStream::Stdout, "ready\u{1b}[2J"),
        Err(runne_api::ProcessHostError::InvalidOutput)
    );
    for text in ["c1\u{009b}sequence", "bidi\u{202e}override"] {
        assert_eq!(
            ProcessOutputChunk::new(1, ProcessOutputStream::Stdout, text),
            Err(runne_api::ProcessHostError::InvalidOutput)
        );
    }
    assert_eq!(
        ProcessOutputChunk::new(
            1,
            ProcessOutputStream::Stdout,
            "x".repeat(MAX_PROCESS_OUTPUT_BYTES + 1)
        ),
        Err(runne_api::ProcessHostError::SizeLimit)
    );
}

#[test]
fn process_output_page_requires_ordered_bounded_chunks() {
    let second = ProcessOutputChunk::new(2, ProcessOutputStream::Stderr, "second").unwrap();
    let first = ProcessOutputChunk::new(1, ProcessOutputStream::Stdout, "first").unwrap();
    assert_eq!(
        ProcessOutputPage::new(2, vec![second.clone(), first]),
        Err(runne_api::ProcessHostError::InvariantViolation)
    );
    assert_eq!(
        ProcessOutputPage::new(0, vec![second]),
        Err(runne_api::ProcessHostError::InvalidLimit)
    );
}

#[test]
fn process_output_page_enforces_encoded_wire_budget() {
    let chunk = ProcessOutputChunk::new(
        1,
        ProcessOutputStream::Stdout,
        "x".repeat(MAX_PROCESS_OUTPUT_BYTES),
    )
    .unwrap();
    let chunks = (0..=MAX_PROCESS_OUTPUT_WIRE_BYTES / MAX_PROCESS_OUTPUT_BYTES)
        .map(|sequence| {
            ProcessOutputChunk::new(
                sequence as u64 + 1,
                ProcessOutputStream::Stdout,
                chunk.text().to_owned(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        ProcessOutputPage::new(MAX_PROCESS_OUTPUT_CHUNKS, chunks),
        Err(runne_api::ProcessHostError::SizeLimit)
    );
}
