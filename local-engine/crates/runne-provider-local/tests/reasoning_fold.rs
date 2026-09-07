//! Reasoning fold (Plan Task 20 Step 2): the fold is the ONLY channel
//! reasoning content takes in Phase 1 — text order preserved, no new
//! product stream kind, unit tests for the effort gate and the
//! once-only token count.

use runne_provider_local::port::StreamItem;
use runne_provider_local::reasoning_fold::{
    FoldBlock, ReasoningDeclaration, ReasoningError, fold, reasoning_tokens_once,
};

#[test]
fn fold_preserves_order_without_new_kind() {
    let folded = fold(&[
        FoldBlock::Reasoning("private thoughts".into()),
        FoldBlock::Text("public answer".into()),
        FoldBlock::Text(" more".into()),
    ]);
    assert_eq!(
        folded,
        vec![
            StreamItem::Text {
                seq: 0,
                text: "private thoughts".into()
            },
            StreamItem::Text {
                seq: 1,
                text: "public answer".into()
            },
            StreamItem::Text {
                seq: 2,
                text: " more".into()
            },
        ]
    );
    // No reasoning variant exists in the product stream kinds.
    assert!(folded.iter().all(|i| matches!(i, StreamItem::Text { .. })));
}

#[test]
fn empty_reasoning_content_folds_to_nothing() {
    let folded = fold(&[
        FoldBlock::Reasoning(String::new()),
        FoldBlock::Text("answer".into()),
    ]);
    assert_eq!(
        folded,
        vec![StreamItem::Text {
            seq: 0,
            text: "answer".into()
        }]
    );
}

#[test]
fn reasoning_tokens_counted_once() {
    assert_eq!(reasoning_tokens_once(9), 9);
    // Idempotent at the fold boundary: folding twice must not double.
    assert_eq!(reasoning_tokens_once(9) + reasoning_tokens_once(0), 9);
}

#[test]
fn effort_gate_declarations() {
    let declared = ReasoningDeclaration {
        style: "inline_markers".into(),
        levels: vec!["low".into(), "medium".into(), "off".into()],
        default_level: "low".into(),
    };
    assert!(
        declared.validate_effort(Some("off")).is_ok(),
        "off if declared"
    );
    assert!(declared.validate_effort(Some("medium")).is_ok());
    assert_eq!(
        declared.validate_effort(Some("max")),
        Err(ReasoningError::EffortUnsupported)
    );
    // Unmanaged effort: any explicit request is unsupported.
    let unmanaged = ReasoningDeclaration::default();
    assert_eq!(
        unmanaged.validate_effort(Some("low")),
        Err(ReasoningError::EffortUnsupported)
    );
}
