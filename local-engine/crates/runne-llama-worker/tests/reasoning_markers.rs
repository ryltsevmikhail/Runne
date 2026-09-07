//! Reasoning marker fixtures (Plan Task 20 Step 1, pinned revision
//! `inline-markers-v1`): open/close, unclosed, interleaved and
//! marker-after-text all classify per the declared semantics.

use runne_llama_worker::reasoning::{Block, PARSER_REVISION, ReasoningError, parse_output};

#[test]
fn parser_revision_is_pinned() {
    assert_eq!(PARSER_REVISION, "inline-markers-v1");
}

#[test]
fn leading_block_classifies() {
    let blocks = parse_output("<think>pondering</think>the answer").expect("parse");
    assert_eq!(
        blocks,
        vec![
            Block::Reasoning("pondering".into()),
            Block::Text("the answer".into()),
        ]
    );
}

#[test]
fn empty_reasoning_block_classifies() {
    let blocks = parse_output("<think></think>answer").expect("parse");
    assert_eq!(
        blocks,
        vec![Block::Reasoning("".into()), Block::Text("answer".into())]
    );
}

#[test]
fn plain_text_has_no_blocks_misclassification() {
    let blocks = parse_output("just text").expect("parse");
    assert_eq!(blocks, vec![Block::Text("just text".into())]);
}

#[test]
fn unclosed_marker_is_parse_failed() {
    assert_eq!(
        parse_output("<think>never closed"),
        Err(ReasoningError::ParseFailed)
    );
}

#[test]
fn interleaved_reasoning_is_parse_failed() {
    assert_eq!(
        parse_output("<think>a</think>text<think>more</think>tail"),
        Err(ReasoningError::ParseFailed)
    );
}

#[test]
fn marker_after_text_is_parse_failed() {
    assert_eq!(
        parse_output("text first <think>later</think>"),
        Err(ReasoningError::ParseFailed)
    );
    // A stray close marker with no block is also out of contract.
    assert_eq!(
        parse_output("text</think>"),
        Err(ReasoningError::ParseFailed)
    );
}
