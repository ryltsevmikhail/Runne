//! Context admission (REQ-PROV-125): the rendered input is quoted
//! under the pinned tokenizer revision and admitted against
//! `context_limit − reserved_output − template_overhead`. A breach is
//! a typed pre-dispatch reject (`ContextExceeded`) with sanitized
//! counts — no prompt content, no host effect, no truncation by the
//! engine (reassembly is the product Context subsystem's job and
//! yields a NEW `ProviderCall`).

use crate::error::ProviderError;
use runne_local_model::tokenizer_quote::{QuoteError, QuoteRevision, token_quote};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextAdmission {
    pub revision: QuoteRevision,
    pub context_limit: u64,
    pub reserved_output_tokens: u64,
    pub template_overhead_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextQuote {
    pub quoted_tokens: u64,
    pub allowed_input_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextAdmissionError {
    /// Typed pre-dispatch reject; sanitized counts only.
    ContextExceeded {
        quoted_tokens: u64,
        context_limit: u64,
        reserved_output_tokens: u64,
    },
    Quote(QuoteError),
}

impl std::fmt::Display for ContextAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContextExceeded {
                quoted_tokens,
                context_limit,
                reserved_output_tokens,
            } => write!(
                f,
                "context exceeded: quoted {quoted_tokens} over {context_limit} − \
                 {reserved_output_tokens} reserved"
            ),
            Self::Quote(e) => write!(f, "tokenizer quote: {e}"),
        }
    }
}

impl std::error::Error for ContextAdmissionError {}

impl From<QuoteError> for ContextAdmissionError {
    fn from(e: QuoteError) -> Self {
        Self::Quote(e)
    }
}

impl From<ContextAdmissionError> for ProviderError {
    fn from(e: ContextAdmissionError) -> Self {
        match e {
            ContextAdmissionError::ContextExceeded {
                quoted_tokens,
                context_limit,
                reserved_output_tokens,
            } => ProviderError::ContextExceeded {
                quoted_tokens,
                context_limit,
                reserved_output_tokens,
            },
            ContextAdmissionError::Quote(q) => ProviderError::TokenizerQuote(q.to_string()),
        }
    }
}

impl ContextAdmission {
    /// Quotes the rendered input and admits it against the context
    /// envelope. Pure: no host effect on any path.
    pub fn admit(&self, rendered_input: &[u8]) -> Result<ContextQuote, ContextAdmissionError> {
        let quoted_tokens = token_quote(self.revision, rendered_input)?
            .saturating_add(self.template_overhead_tokens);
        let allowed = self
            .context_limit
            .saturating_sub(self.reserved_output_tokens);
        if quoted_tokens > allowed {
            return Err(ContextAdmissionError::ContextExceeded {
                quoted_tokens,
                context_limit: self.context_limit,
                reserved_output_tokens: self.reserved_output_tokens,
            });
        }
        Ok(ContextQuote {
            quoted_tokens,
            allowed_input_tokens: allowed,
        })
    }
}
