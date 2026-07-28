use serde_json::Value;
use thiserror::Error;

/// Invalid output bound or overflow reference.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidOutputContract {
    /// Every output bound must be non-zero.
    #[error("tool output bounds must be non-zero")]
    ZeroBound,
    /// Blob reference must be printable, non-empty and bounded.
    #[error("invalid overflow blob reference")]
    InvalidBlobRef,
}

/// Content-addressed reference for output omitted from the inline result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef(String);

impl BlobRef {
    /// Constructs a bounded printable reference.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidOutputContract> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(InvalidOutputContract::InvalidBlobRef);
        }
        Ok(Self(value))
    }

    /// Returns the reference text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact inline output limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolOutputBounds {
    max_bytes: usize,
    max_lines: usize,
    max_items: usize,
}

impl ToolOutputBounds {
    /// Constructs non-zero byte, line and item limits.
    pub fn new(
        max_bytes: usize,
        max_lines: usize,
        max_items: usize,
    ) -> Result<Self, InvalidOutputContract> {
        if max_bytes == 0 || max_lines == 0 || max_items == 0 {
            return Err(InvalidOutputContract::ZeroBound);
        }
        Ok(Self {
            max_bytes,
            max_lines,
            max_items,
        })
    }
}

/// Raw executor output awaiting mandatory bounds.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RawToolOutput {
    /// Combined bounded-stream bytes.
    pub bytes: Vec<u8>,
    /// Structured text lines.
    pub lines: Vec<String>,
    /// Structured result items.
    pub items: Vec<Value>,
    /// Required content-addressed reference when any output is omitted.
    pub overflow_blob: Option<BlobRef>,
}

/// Bounded inline tool output.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolOutput {
    bytes: Vec<u8>,
    lines: Vec<String>,
    items: Vec<Value>,
    truncated: bool,
    overflow_blob: Option<BlobRef>,
}

impl ToolOutput {
    pub(crate) fn bound(raw: RawToolOutput, bounds: ToolOutputBounds) -> Result<Self, ()> {
        let mut remaining_bytes = bounds.max_bytes;
        let bytes: Vec<u8> = raw.bytes.iter().copied().take(remaining_bytes).collect();
        remaining_bytes -= bytes.len();

        let mut lines = Vec::new();
        for line in raw.lines.iter().take(bounds.max_lines) {
            if line.len() > remaining_bytes {
                break;
            }
            remaining_bytes -= line.len();
            lines.push(line.clone());
        }

        let mut items = Vec::new();
        for item in raw.items.iter().take(bounds.max_items) {
            let encoded_len = serde_json::to_vec(item).map_err(|_| ())?.len();
            if encoded_len > remaining_bytes {
                break;
            }
            remaining_bytes -= encoded_len;
            items.push(item.clone());
        }

        let truncated = bytes.len() != raw.bytes.len()
            || lines.len() != raw.lines.len()
            || items.len() != raw.items.len();
        if truncated && raw.overflow_blob.is_none() {
            return Err(());
        }
        Ok(Self {
            bytes,
            lines,
            items,
            truncated,
            overflow_blob: raw.overflow_blob,
        })
    }

    /// Returns bounded bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns bounded lines.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Returns bounded structured items.
    pub fn items(&self) -> &[Value] {
        &self.items
    }

    /// Reports whether output was omitted.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Returns the mandatory overflow reference when truncated.
    pub const fn overflow_blob(&self) -> Option<&BlobRef> {
        self.overflow_blob.as_ref()
    }
}
