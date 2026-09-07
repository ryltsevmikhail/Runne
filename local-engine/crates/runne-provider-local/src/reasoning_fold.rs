//! Reasoning fold (REQ-PROV-124, Plan Task 20 Step 2): the adapter-side
//! fold of engine-internal reasoning/text blocks into EXISTING
//! normalized kinds. The product stream gains no reasoning variant
//! (OQ-LE-010); reasoning content flows only through this fold as
//! data, order is preserved, and `reasoning_output_tokens` is counted
//! exactly once from terminal usage.

use crate::port::StreamItem;

/// Mirror of the worker parser's classified blocks (bytes-only
/// content; no product stream kind exists for reasoning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldBlock {
    Reasoning(String),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReasoningError {
    /// Output violates the declared parser revision semantics.
    ParseFailed,
    /// Requested effort not declared by the manifest (or the manifest
    /// does not manage effort at all). `off` only if declared.
    EffortUnsupported,
}

/// Manifest `capabilities.reasoning` declaration (subset relevant to
/// the fold boundary).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReasoningDeclaration {
    /// `inline_markers` for the pinned parser revision.
    pub style: String,
    /// Declared levels ⊆ {off, low, medium, high, max}; empty = effort
    /// not managed.
    pub levels: Vec<String>,
    pub default_level: String,
}

impl ReasoningDeclaration {
    pub const KNOWN_LEVELS: [&str; 5] = ["off", "low", "medium", "high", "max"];

    /// Validates a requested `reasoning_effort` (from the sampling
    /// profile) against the declared levels. Empty `levels` = effort
    /// unmanaged → any explicit request is unsupported.
    pub fn validate_effort(&self, requested: Option<&str>) -> Result<(), ReasoningError> {
        let Some(req) = requested else {
            return Ok(());
        };
        if !Self::KNOWN_LEVELS.contains(&req) || !self.levels.iter().any(|l| l == req) {
            return Err(ReasoningError::EffortUnsupported);
        }
        Ok(())
    }
}

/// Folds classified blocks into existing stream kinds: text order is
/// preserved, reasoning content is delivered as data inside `Text`
/// deltas, and the returned stream contains NO new kind.
pub fn fold(blocks: &[FoldBlock]) -> Vec<StreamItem> {
    let mut seq = 0u64;
    let mut out = Vec::new();
    for block in blocks {
        match block {
            FoldBlock::Reasoning(content) | FoldBlock::Text(content) => {
                if content.is_empty() {
                    continue;
                }
                out.push(StreamItem::Text {
                    seq,
                    text: content.clone(),
                });
                seq += 1;
            }
        }
    }
    out
}

/// Counts reasoning output tokens ONCE (from the terminal usage
/// report); the caller passes the usage item's split.
pub fn reasoning_tokens_once(usage_reasoning_tokens: u64) -> u64 {
    usage_reasoning_tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effort_gate_matches_declaration() {
        let mut d = ReasoningDeclaration {
            style: "inline_markers".into(),
            levels: vec!["low".into(), "high".into()],
            default_level: "low".into(),
        };
        assert!(d.validate_effort(Some("high")).is_ok());
        assert_eq!(
            d.validate_effort(Some("off")),
            Err(ReasoningError::EffortUnsupported)
        );
        d.levels.clear();
        assert_eq!(
            d.validate_effort(Some("low")),
            Err(ReasoningError::EffortUnsupported)
        );
        assert!(d.validate_effort(None).is_ok(), "absence is always fine");
    }

    #[test]
    fn fold_preserves_order_and_kinds() {
        let folded = fold(&[
            FoldBlock::Reasoning("thinking".into()),
            FoldBlock::Text("answer".into()),
        ]);
        assert_eq!(folded.len(), 2);
        assert!(folded.iter().all(|i| matches!(i, StreamItem::Text { .. })));
        assert_eq!(
            folded,
            vec![
                StreamItem::Text {
                    seq: 0,
                    text: "thinking".into()
                },
                StreamItem::Text {
                    seq: 1,
                    text: "answer".into()
                },
            ]
        );
    }
}
