#![allow(dead_code)]
#[cfg(test)]
pub(super) use super::approvals::approve;
pub(super) use super::approvals::{
    ApprovalReplayIdentity, ApprovalSet, ConsumedAttempt, CostApproval, CredentialApproval,
    NetworkApproval, ValidatedApprovalTransaction,
};
use core::fmt;
use runne_provider_deepseek::canary::CanaryCandidate;

const MODEL: &str = "deepseek-flash";
const METHOD: &str = "POST";
const ORIGIN: &str = "https://api.deepseek.com";
const PRICING: &str = "deepseek-flash-peak-2026-09-21/1";
#[derive(Clone, PartialEq)]
pub(super) enum TrustRoots {
    SystemTrustRootsOnly,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ApprovalError {
    MissingCredential,
    MissingNetwork,
    MissingCost,
    InvalidTime,
    BindingMismatch,
    CostCapExceeded,
    AlreadyClaimed,
}
#[derive(Clone, Copy)]
pub(super) struct EvaluationTime(u64);
impl EvaluationTime {
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }
}
type Network = (
    &'static str,
    &'static str,
    TrustRoots,
    bool,
    bool,
    bool,
    u64,
    u64,
    u64,
);
type Cost = (&'static str, &'static str, u64, u64, u64, u64);
#[derive(Clone, PartialEq)]
pub(super) struct AuthorityBindings {
    pub(super) replay: ApprovalReplayIdentity,
    common: String,
    pub(super) claim_id: &'static str,
    pub(super) single_use: bool,
    time: (u64, u64),
    network: Network,
    cost: Cost,
}
impl AuthorityBindings {
    pub(super) fn for_candidate(candidate: &CanaryCandidate) -> Self {
        let evidence = candidate.evidence();
        Self {
            replay: ApprovalReplayIdentity(
                *evidence.candidate_digest(),
                *evidence.profile_digest(),
                1,
                "operator",
                "external",
                "session",
                1,
                "claim",
            ),
            common: format!(
                "{}\0{}\0{}",
                candidate.provider(),
                candidate.request_model(),
                candidate.path()
            ),
            claim_id: "claim",
            single_use: true,
            time: (10, 20),
            network: (
                METHOD,
                ORIGIN,
                TrustRoots::SystemTrustRootsOnly,
                true,
                true,
                true,
                10,
                30,
                120,
            ),
            cost: (MODEL, PRICING, 256, 16, 1_760, 2_000),
        }
    }
    #[cfg(test)]
    pub(super) fn mismatch_path(&mut self) {
        self.common.push('x');
    }
    #[cfg(test)]
    pub(super) fn disable_single_use(&mut self) {
        self.single_use = false;
    }
    #[cfg(test)]
    pub(super) fn mismatch_claim_id(&mut self) {
        self.claim_id = "other";
        self.replay.7 = "other";
    }
    #[cfg(test)]
    pub(super) fn raw_sentinel(&mut self) {
        self.replay.2 = 9;
        self.replay.3 = "principal-raw";
        self.replay.4 = "authority-raw";
        self.replay.5 = "session-raw";
    }
    #[cfg(test)]
    pub(super) fn clock_rolled_back(&mut self) {
        self.time = (30, 40);
    }
    #[cfg(test)]
    pub(super) fn zero_ttl(&mut self) {
        self.time = (20, 20);
    }
    #[cfg(test)]
    pub(super) fn expired_at_boundary(&mut self) {
        self.time = (10, 15);
    }
    #[cfg(test)]
    pub(super) fn cost_cap_over(&mut self) {
        self.cost.5 = 2_001;
    }
    fn common_matches(&self, other: &Self) -> bool {
        self.replay == other.replay
            && self.common == other.common
            && self.claim_id == other.claim_id
            && self.single_use
            && other.single_use
            && self.time == other.time
    }
}
impl fmt::Debug for AuthorityBindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorityBindings")
    }
}
pub(super) mod sealed {
    pub trait Sealed {}
}
pub(super) trait ApprovalTransactionAuthority: sealed::Sealed {
    fn preview(&self) -> Result<ApprovalTransaction<'_>, ApprovalError>;
    fn consume_all(
        &mut self,
        ticket: ValidatedApprovalTransaction,
    ) -> Result<ClaimBundle, ApprovalError>;
}
pub(super) struct OpaqueHandle([u8; 16]);
pub(super) struct CredentialClaim {
    bindings: AuthorityBindings,
    pub(super) handle: OpaqueHandle,
}
pub(super) struct NetworkClaim {
    bindings: AuthorityBindings,
}
pub(super) struct CostClaim {
    bindings: AuthorityBindings,
}
macro_rules! redacted { ($($type:ty),+ $(,)?) => { $(impl fmt::Debug for $type { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("ExternalClaim") } })+ }; }
redacted!(CredentialClaim, NetworkClaim, CostClaim);
pub(super) struct ClaimBundle {
    pub(super) credential: Option<CredentialClaim>,
    pub(super) network: Option<NetworkClaim>,
    pub(super) cost: Option<CostClaim>,
}
#[cfg(test)]
impl ClaimBundle {
    pub(super) fn fake(bindings: AuthorityBindings) -> Self {
        Self {
            credential: Some(CredentialClaim {
                bindings: bindings.clone(),
                handle: OpaqueHandle([0; 16]),
            }),
            network: Some(NetworkClaim {
                bindings: bindings.clone(),
            }),
            cost: Some(CostClaim { bindings }),
        }
    }
    pub(super) fn remove(&mut self, claim: u8) {
        match claim {
            0 => self.credential = None,
            1 => self.network = None,
            _ => self.cost = None,
        }
    }
    pub(super) fn bindings_mut(&mut self, claim: u8) -> &mut AuthorityBindings {
        match claim {
            0 => &mut self.credential.as_mut().unwrap().bindings,
            1 => &mut self.network.as_mut().unwrap().bindings,
            _ => &mut self.cost.as_mut().unwrap().bindings,
        }
    }
}
impl ClaimBundle {
    pub(super) const fn is_complete(&self) -> bool {
        self.credential.is_some() && self.network.is_some() && self.cost.is_some()
    }
    pub(super) fn identity(&self) -> Option<ApprovalReplayIdentity> {
        self.credential
            .as_ref()
            .map(|claim| (&claim.bindings).into())
    }
}
impl fmt::Debug for ClaimBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimBundle")
    }
}
pub(super) struct ApprovalTransaction<'a> {
    credential: Option<&'a CredentialClaim>,
    network: Option<&'a NetworkClaim>,
    cost: Option<&'a CostClaim>,
}
impl<'a> From<Option<&'a ClaimBundle>> for ApprovalTransaction<'a> {
    fn from(bundle: Option<&'a ClaimBundle>) -> Self {
        match bundle {
            Some(bundle) => Self {
                credential: bundle.credential.as_ref(),
                network: bundle.network.as_ref(),
                cost: bundle.cost.as_ref(),
            },
            None => Self {
                credential: None,
                network: None,
                cost: None,
            },
        }
    }
}
impl fmt::Debug for ApprovalTransaction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalTransaction")
    }
}
redacted!(CredentialApproval, NetworkApproval, CostApproval);
pub(super) fn validate(
    expected: &AuthorityBindings,
    now: EvaluationTime,
    transaction: ApprovalTransaction<'_>,
) -> Result<ValidatedApprovalTransaction, ApprovalError> {
    let credential = transaction
        .credential
        .ok_or(ApprovalError::MissingCredential)?;
    let network = transaction.network.ok_or(ApprovalError::MissingNetwork)?;
    let cost = transaction.cost.ok_or(ApprovalError::MissingCost)?;
    for bindings in [&credential.bindings, &network.bindings, &cost.bindings] {
        validate_common(bindings, expected, now)?;
    }
    if cost.bindings.cost.5 > 2_000 {
        return Err(ApprovalError::CostCapExceeded);
    }
    if !network_matches(&network.bindings, expected) || !cost_matches(&cost.bindings, expected) {
        return Err(ApprovalError::BindingMismatch);
    }
    Ok(ValidatedApprovalTransaction((&credential.bindings).into()))
}
fn validate_common(
    actual: &AuthorityBindings,
    expected: &AuthorityBindings,
    now: EvaluationTime,
) -> Result<(), ApprovalError> {
    if now.0 < actual.time.0 || actual.time.1 <= actual.time.0 || now.0 >= actual.time.1 {
        return Err(ApprovalError::InvalidTime);
    }
    actual
        .common_matches(expected)
        .then_some(())
        .ok_or(ApprovalError::BindingMismatch)
}
fn network_matches(actual: &AuthorityBindings, expected: &AuthorityBindings) -> bool {
    actual.network
        == (
            METHOD,
            ORIGIN,
            TrustRoots::SystemTrustRootsOnly,
            true,
            true,
            true,
            10,
            30,
            120,
        )
        && actual.network == expected.network
}
fn cost_matches(actual: &AuthorityBindings, expected: &AuthorityBindings) -> bool {
    actual.cost == (MODEL, PRICING, 256, 16, 1_760, 2_000) && actual.cost == expected.cost
}
