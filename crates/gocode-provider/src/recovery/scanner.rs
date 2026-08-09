use zeroize::Zeroizing;

use super::{ScannerError, ScannerTerminalDisposition, ScannerUncertainReason, TailBinding};

const MAX_SCANNED_OUTPUT_BYTES: usize = 4_194_288;

/// Ephemeral credential matcher boundary. Implementations never expose matcher material.
pub trait CredentialMatcher: Send + Sync {
    /// Returns the currently available immutable matcher epoch.
    fn epoch(&self) -> Result<u64, ScannerError>;
    /// Returns the maximum possible match width required for boundary withholding.
    fn maximum_match_len(&self) -> Result<usize, ScannerError>;
    /// Classifies an ephemeral provider byte window.
    fn contains_match(&self, bytes: &[u8]) -> Result<bool, ScannerError>;
}

/// Ephemeral result of scanning one provider chunk before any journal append.
pub struct ScanStep {
    safe_prefix: Zeroizing<Vec<u8>>,
    withheld_tail: Zeroizing<Vec<u8>>,
    binding: TailBinding,
    safe_prefix_high_water: u64,
    disposition: Option<ScannerTerminalDisposition>,
}

impl ScanStep {
    /// Returns safe bytes that may enter only a publication-suppressed staging journal.
    pub fn safe_prefix(&self) -> &[u8] {
        &self.safe_prefix
    }
    /// Returns the next exact tail binding.
    pub const fn binding(&self) -> TailBinding {
        self.binding
    }
    /// Returns the next safe-prefix high-water.
    pub const fn safe_prefix_high_water(&self) -> u64 {
        self.safe_prefix_high_water
    }
    /// Returns a terminal failure when classification cannot continue safely.
    pub const fn disposition(&self) -> Option<ScannerTerminalDisposition> {
        self.disposition
    }
    /// Consumes the step and transfers withheld bytes only to native storage.
    pub fn into_withheld_tail(self) -> Zeroizing<Vec<u8>> {
        self.withheld_tail
    }
}

/// Scans one provider chunk while withholding enough suffix for every cross-boundary match.
pub fn scan_provider_chunk<M: CredentialMatcher + ?Sized>(
    matcher: &M,
    binding: TailBinding,
    previous_tail: Zeroizing<Vec<u8>>,
    provider_bytes: &[u8],
    safe_prefix_high_water: u64,
) -> Result<ScanStep, ScannerError> {
    let cursor = binding
        .cursor()
        .checked_add(
            u64::try_from(provider_bytes.len()).map_err(|_| ScannerError::OutputLimitExceeded)?,
        )
        .ok_or(ScannerError::OutputLimitExceeded)?;
    let next_binding = binding.at_cursor(cursor);
    if matcher
        .epoch()
        .map_err(|_| ScannerError::MatcherUnavailable)?
        != binding.matcher_epoch()
    {
        return Ok(terminal_step(
            next_binding,
            safe_prefix_high_water,
            ScannerUncertainReason::CredentialMatcherUnavailable,
        ));
    }
    let maximum = match matcher.maximum_match_len() {
        Ok(value) if value > 0 && value <= MAX_SCANNED_OUTPUT_BYTES => value,
        Ok(_) => return Err(ScannerError::InvalidBinding),
        Err(_) => {
            return Ok(terminal_step(
                next_binding,
                safe_prefix_high_water,
                ScannerUncertainReason::CredentialMatcherUnavailable,
            ));
        }
    };
    let length = previous_tail
        .len()
        .checked_add(provider_bytes.len())
        .ok_or(ScannerError::OutputLimitExceeded)?;
    if length > MAX_SCANNED_OUTPUT_BYTES {
        return Ok(limit_step(next_binding, safe_prefix_high_water));
    }
    let mut combined = Zeroizing::new(Vec::with_capacity(length));
    combined.extend_from_slice(&previous_tail);
    combined.extend_from_slice(provider_bytes);
    match matcher.contains_match(&combined) {
        Ok(true) => {
            return Ok(terminal_step(
                next_binding,
                safe_prefix_high_water,
                ScannerUncertainReason::SecretDetected,
            ));
        }
        Err(ScannerError::MatcherUnavailable) => {
            return Ok(terminal_step(
                next_binding,
                safe_prefix_high_water,
                ScannerUncertainReason::CredentialMatcherUnavailable,
            ));
        }
        Err(_) => {
            return Ok(terminal_step(
                next_binding,
                safe_prefix_high_water,
                ScannerUncertainReason::RedactionScannerUnavailable,
            ));
        }
        Ok(false) => {}
    }
    let withheld = maximum.saturating_sub(1).min(combined.len());
    let split = combined.len() - withheld;
    let safe_prefix = Zeroizing::new(combined[..split].to_vec());
    let withheld_tail = Zeroizing::new(combined[split..].to_vec());
    let next_high_water = safe_prefix_high_water
        .checked_add(
            u64::try_from(safe_prefix.len()).map_err(|_| ScannerError::OutputLimitExceeded)?,
        )
        .ok_or(ScannerError::OutputLimitExceeded)?;
    Ok(ScanStep {
        safe_prefix,
        withheld_tail,
        binding: next_binding,
        safe_prefix_high_water: next_high_water,
        disposition: None,
    })
}

fn terminal_step(
    binding: TailBinding,
    high_water: u64,
    reason: ScannerUncertainReason,
) -> ScanStep {
    ScanStep {
        safe_prefix: Zeroizing::new(Vec::new()),
        withheld_tail: Zeroizing::new(Vec::new()),
        binding,
        safe_prefix_high_water: high_water,
        disposition: Some(ScannerTerminalDisposition::Uncertain(reason)),
    }
}

fn limit_step(binding: TailBinding, high_water: u64) -> ScanStep {
    ScanStep {
        safe_prefix: Zeroizing::new(Vec::new()),
        withheld_tail: Zeroizing::new(Vec::new()),
        binding,
        safe_prefix_high_water: high_water,
        disposition: Some(ScannerTerminalDisposition::OutputLimitExceeded),
    }
}
