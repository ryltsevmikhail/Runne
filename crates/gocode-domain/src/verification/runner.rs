//! L0-L3 runner interfaces (stubs for Phase 9A implementation).

use crate::verification::identity::*;
use crate::verification::digest::VerificationDigest;

/// Result of running a verification layer.
#[derive(Clone, Debug)]
pub struct RunnerOutput {
    pub layer: String,
    pub passed: bool,
    pub evidence_count: u32,
    pub output_digest: VerificationDigest,
}

/// L0 runner — deterministic contract tests.
pub struct L0Runner;

impl L0Runner {
    pub fn run(seed: u64) -> RunnerOutput {
        let digest = crate::verification::digest::DigestContract::new("gocode:l0-runner:v1")
            .compute(&[&seed.to_be_bytes()]);
        RunnerOutput { layer: "L0".into(), passed: true, evidence_count: 1, output_digest: digest }
    }
}

/// L1 runner — golden trace comparison.
pub struct L1Runner;

impl L1Runner {
    pub fn run(golden_revision: &str, actual_digest: &VerificationDigest) -> RunnerOutput {
        let contract = crate::verification::digest::DigestContract::new("gocode:l1-runner:v1");
        let digest = contract.compute(&[golden_revision.as_bytes(), actual_digest.as_bytes()]);
        let passed = !actual_digest.as_bytes().iter().all(|b| *b == 0);
        RunnerOutput { layer: "L1".into(), passed, evidence_count: 1, output_digest: digest }
    }
}

/// L2-S runner — simulated integration.
pub struct L2SRunner;

impl L2SRunner {
    pub fn run(seed: u64) -> RunnerOutput {
        let digest = crate::verification::digest::DigestContract::new("gocode:l2s-runner:v1")
            .compute(&[&seed.to_be_bytes()]);
        RunnerOutput { layer: "L2-S".into(), passed: true, evidence_count: 1, output_digest: digest }
    }
}

/// L2-I runner — real local dependency integration.
pub struct L2IRunner;

impl L2IRunner {
    pub fn run(platform_available: bool) -> RunnerOutput {
        RunnerOutput { layer: "L2-I".into(), passed: platform_available, evidence_count: if platform_available { 1 } else { 0 }, output_digest: VerificationDigest::from_bytes([0; 32]) }
    }
}

/// L4 authorization — bounded live evaluation.
pub struct L4Authorization {
    pub request_count: u64,
    pub token_budget: u64,
    pub used_requests: u64,
    pub used_tokens: u64,
    pub revoked: bool,
}

impl L4Authorization {
    pub fn new(request_count: u64, token_budget: u64) -> Self {
        Self { request_count, token_budget, used_requests: 0, used_tokens: 0, revoked: false }
    }

    /// Atomically reserve budget. Fails if any dimension exhausted.
    pub fn reserve(&mut self, requests: u64, tokens: u64) -> Result<(), L4Error> {
        if self.revoked { return Err(L4Error::Revoked); }
        if self.used_requests + requests > self.request_count { return Err(L4Error::BudgetExceeded("request_count".into())); }
        if self.used_tokens + tokens > self.token_budget { return Err(L4Error::BudgetExceeded("token_budget".into())); }
        self.used_requests += requests;
        self.used_tokens += tokens;
        Ok(())
    }

    pub fn revoke(&mut self) { self.revoked = true; }
}

#[derive(Debug, PartialEq, Eq)]
pub enum L4Error { BudgetExceeded(String), Revoked }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::digest::VerificationDigest;

    #[test] fn l0_runner_deterministic() { let r1 = L0Runner::run(42); let r2 = L0Runner::run(42); assert_eq!(r1.output_digest, r2.output_digest); }
    #[test] fn l0_runner_different_seed() { assert_ne!(L0Runner::run(1).output_digest, L0Runner::run(2).output_digest); }
    #[test] fn l1_runner_matching_pass() { let d = VerificationDigest::from_bytes([1; 32]); assert!(L1Runner::run("v1", &d).passed); }
    #[test] fn l2s_runner_deterministic() { assert_eq!(L2SRunner::run(42).output_digest, L2SRunner::run(42).output_digest); }
    #[test] fn l2i_runner_platform_unavailable() { assert!(!L2IRunner::run(false).passed); }

    #[test] fn l4_reserve_within_budget() { let mut a = L4Authorization::new(10, 1000); assert!(a.reserve(1, 100).is_ok()); }
    #[test] fn l4_reserve_exceeds_budget() { let mut a = L4Authorization::new(1, 100); a.reserve(1, 0).unwrap(); assert!(a.reserve(1, 0).is_err()); }

    #[test]
    fn l4_reserve_atomic_on_failure() {
        let mut a = L4Authorization::new(10, 5);
        let result = a.reserve(0, 10);
        assert!(result.is_err());
        assert_eq!(a.used_tokens, 0);
    }
}
