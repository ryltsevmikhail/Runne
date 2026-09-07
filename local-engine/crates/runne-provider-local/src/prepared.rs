//! Prepared request: deterministic, effect-free output of `prepare`.

/// Identity + render binding produced by an effect-free `prepare`. The
/// render digest pins the attempt: same inputs → same digest, any
/// identity-bearing change → a different attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub call_id: [u8; 16],
    pub model_identity: String,
    /// sha256 over the canonical render inputs.
    pub render_digest: String,
    /// sha256 over the canonical effective sampling map.
    pub sampling_digest: String,
    /// Structured-output schema digest (schema-json mode only).
    pub structured: Option<String>,
    /// Host-rendered prompt text captured at prepare time; flows to
    /// real backends at dispatch (fakes ignore it).
    pub prompt: String,
}
