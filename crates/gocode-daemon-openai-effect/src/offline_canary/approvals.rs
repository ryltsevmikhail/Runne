#![allow(dead_code)]

use core::fmt;

use super::authority::{
    ApprovalError, ApprovalTransactionAuthority, AuthorityBindings, ClaimBundle, CredentialClaim,
    EvaluationTime, OpaqueHandle, validate,
};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ApprovalReplayIdentity(
    pub(super) [u8; 32],
    pub(super) [u8; 32],
    pub(super) u64,
    pub(super) &'static str,
    pub(super) &'static str,
    pub(super) &'static str,
    pub(super) u64,
    pub(super) &'static str,
);
impl From<&AuthorityBindings> for ApprovalReplayIdentity {
    fn from(value: &AuthorityBindings) -> Self {
        value.replay.clone()
    }
}

pub(super) struct CredentialApproval {
    handle: OpaqueHandle,
    replay: ApprovalReplayIdentity,
}
pub(super) struct NetworkApproval {
    replay: ApprovalReplayIdentity,
}
pub(super) struct CostApproval {
    replay: ApprovalReplayIdentity,
}
pub(super) struct ConsumedAttempt(ApprovalReplayIdentity);
pub(super) struct ApprovalSet {
    credential: CredentialApproval,
    network: NetworkApproval,
    cost: CostApproval,
    replay: ApprovalReplayIdentity,
}
impl ApprovalSet {
    pub(super) fn from_bundle(bundle: ClaimBundle, replay: ApprovalReplayIdentity) -> Self {
        let ClaimBundle {
            credential: Some(CredentialClaim { handle, .. }),
            network: Some(_),
            cost: Some(_),
        } = bundle
        else {
            unreachable!("validated authority returns complete bundle")
        };
        Self {
            credential: CredentialApproval {
                handle,
                replay: replay.clone(),
            },
            network: NetworkApproval {
                replay: replay.clone(),
            },
            cost: CostApproval {
                replay: replay.clone(),
            },
            replay,
        }
    }
    pub(super) fn replay(&self) -> &ApprovalReplayIdentity {
        &self.replay
    }
    pub(super) fn consume(self) -> ConsumedAttempt {
        let Self {
            credential,
            network,
            cost,
            replay,
        } = self;
        let _ = (credential, network, cost);
        ConsumedAttempt(replay)
    }
}
impl fmt::Debug for ApprovalSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalSet")
    }
}

pub(super) struct PossibleDispatchBoundaryWitness(ApprovalReplayIdentity);
impl PossibleDispatchBoundaryWitness {
    pub(super) fn matches(&self, replay: &ApprovalReplayIdentity) -> bool {
        &self.0 == replay
    }
}
impl fmt::Debug for PossibleDispatchBoundaryWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PossibleDispatchBoundaryWitness")
    }
}

pub(super) struct ValidatedApprovalTransaction(pub(super) ApprovalReplayIdentity);
impl ValidatedApprovalTransaction {
    pub(super) fn matches(&self, bundle: Option<&ClaimBundle>) -> bool {
        bundle.and_then(ClaimBundle::identity).as_ref() == Some(&self.0)
    }
    pub(super) const fn identity(&self) -> &ApprovalReplayIdentity {
        &self.0
    }
    pub(super) fn into_identity(self) -> ApprovalReplayIdentity {
        self.0
    }
}
pub(super) fn approve(
    expected: &AuthorityBindings,
    now: EvaluationTime,
    authority: &mut impl ApprovalTransactionAuthority,
) -> Result<ApprovalSet, ApprovalError> {
    let ticket = validate(expected, now, authority.preview()?)?;
    let replay = ticket.identity().clone();
    authority
        .consume_all(ticket)
        .map(|bundle| ApprovalSet::from_bundle(bundle, replay))
}
pub(super) mod sealed {
    pub trait Sealed {}
}
#[cfg(test)]
pub(super) trait PossibleDispatchBoundaryMint: sealed::Sealed {
    fn mint_replay(&self, approvals: &ApprovalSet) -> ApprovalReplayIdentity;
}
#[cfg(test)]
pub(super) fn mint_possible_dispatch_boundary(
    approvals: &ApprovalSet,
    mint: &impl PossibleDispatchBoundaryMint,
) -> PossibleDispatchBoundaryWitness {
    PossibleDispatchBoundaryWitness(mint.mint_replay(approvals))
}
