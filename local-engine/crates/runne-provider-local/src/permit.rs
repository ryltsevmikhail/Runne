//! Application-owned ports consumed by the adapter (Task 8 interfaces).
//! The adapter never self-admits and never self-settles.

use crate::error::ProviderError;

/// Resolves the exact already-admitted execution permit for an attempt.
/// Absence or conflict rejects dispatch before any host effect.
pub trait LocalExecutionPermitPort: Send + Sync {
    fn resolve_consumed(&self, attempt_id: &[u8; 16]) -> Result<bool, ProviderError>;
}

/// The only adapter→authoritative accounting boundary. Settlement is
/// exactly-once per attempt; the normalized stream itself never carries
/// authority.
pub trait LocalUsageSettlementPort: Send + Sync {
    fn settle_once(&mut self, attempt_id: &[u8; 16], input_tokens: u64, output_tokens: u64);
}
