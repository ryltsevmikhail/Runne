//! Reasoning parser (REQ-PROV-124), pinned revision
//! `inline-markers-v1`: single leading `<think>…</think>` block in the
//! text stream. Unclosed markers at terminal, markers after text and
//! interleaved reasoning are all OUT of the declared semantics and
//! fail typed (`ParseFailed`) — never a heuristic and never a
//! transport `MalformedStream`.

pub const PARSER_REVISION: &str = "inline-markers-v1";
pub const OPEN_MARKER: &str = "<think>";
pub const CLOSE_MARKER: &str = "</think>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReasoningError {
    /// Output violates the declared parser revision semantics.
    ParseFailed,
}

/// One classified content block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Reasoning(String),
    Text(String),
}

/// Classifies the COMPLETE output text at terminal time.
pub fn parse_output(text: &str) -> Result<Vec<Block>, ReasoningError> {
    if let Some(rest) = text.strip_prefix(OPEN_MARKER) {
        let (reasoning, after) = rest
            .split_once(CLOSE_MARKER)
            .ok_or(ReasoningError::ParseFailed)?;
        if after.contains(OPEN_MARKER) || after.contains(CLOSE_MARKER) {
            // Interleaved reasoning after text.
            return Err(ReasoningError::ParseFailed);
        }
        return Ok(vec![
            Block::Reasoning(reasoning.into()),
            Block::Text(after.into()),
        ]);
    }
    if text.contains(OPEN_MARKER) || text.contains(CLOSE_MARKER) {
        // Markers outside a leading block.
        return Err(ReasoningError::ParseFailed);
    }
    Ok(vec![Block::Text(text.into())])
}
