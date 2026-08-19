//! Closed publication-effect commands and domain-separated fingerprints.
#![allow(clippy::missing_errors_doc, dead_code, clippy::redundant_pub_crate)]

use sha2::{Digest as _, Sha256};

use crate::Digest;
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationEffectError, PublicationEffectScope,
    PublicationEffectState, ReconcileOutcome,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationEffectContext {
    pub(crate) observed_at: u64,
    pub(crate) revocation_epoch: u64,
    pub(crate) allowlist_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicationEffectCommand {
    Claim {
        id: String,
        scope: PublicationEffectScope,
        context: PublicationEffectContext,
    },
    Dispatch {
        id: String,
        scope: PublicationEffectScope,
        context: PublicationEffectContext,
        capability: Digest,
    },
    MarkUncertain {
        id: String,
        scope: PublicationEffectScope,
        capability: Digest,
    },
    SucceedSettlement {
        id: String,
        scope: PublicationEffectScope,
        capability: Digest,
        evidence: Digest,
    },
    Reconcile {
        id: String,
        scope: PublicationEffectScope,
        capability: Digest,
        result: ReconcileOutcome,
        evidence: Digest,
    },
    Reclaim {
        id: String,
        scope: PublicationEffectScope,
        context: PublicationEffectContext,
        capability: Digest,
    },
}

impl PublicationEffectCommand {
    pub(crate) fn claim(
        id: &str,
        scope: &PublicationEffectScope,
        context: PublicationEffectContext,
    ) -> Self {
        Self::Claim {
            id: id.into(),
            scope: scope.clone(),
            context,
        }
    }
    pub(crate) fn dispatch(
        id: &str,
        scope: &PublicationEffectScope,
        context: PublicationEffectContext,
        capability: &FixturePublicationDispatch,
    ) -> Self {
        Self::Dispatch {
            id: id.into(),
            scope: scope.clone(),
            context,
            capability: capability.capability(),
        }
    }
    pub(crate) fn mark_uncertain(
        id: &str,
        scope: &PublicationEffectScope,
        capability: &FixturePublicationDispatch,
    ) -> Self {
        Self::MarkUncertain {
            id: id.into(),
            scope: scope.clone(),
            capability: capability.capability(),
        }
    }
    pub(crate) fn succeed(
        id: &str,
        scope: &PublicationEffectScope,
        capability: &FixturePublicationDispatch,
        evidence: Digest,
    ) -> Self {
        Self::SucceedSettlement {
            id: id.into(),
            scope: scope.clone(),
            capability: capability.capability(),
            evidence,
        }
    }
    pub(crate) fn reconcile(
        id: &str,
        scope: &PublicationEffectScope,
        capability: &FixturePublicationDispatch,
        result: ReconcileOutcome,
        evidence: Digest,
    ) -> Self {
        Self::Reconcile {
            id: id.into(),
            scope: scope.clone(),
            capability: capability.capability(),
            result,
            evidence,
        }
    }
    pub(crate) fn reclaim(
        id: &str,
        scope: &PublicationEffectScope,
        context: PublicationEffectContext,
        capability: &FixturePublicationDispatch,
    ) -> Self {
        Self::Reclaim {
            id: id.into(),
            scope: scope.clone(),
            context,
            capability: capability.capability(),
        }
    }
    pub(crate) fn id(&self) -> &str {
        match self {
            Self::Claim { id, .. }
            | Self::Dispatch { id, .. }
            | Self::MarkUncertain { id, .. }
            | Self::SucceedSettlement { id, .. }
            | Self::Reconcile { id, .. }
            | Self::Reclaim { id, .. } => id,
        }
    }
    pub(crate) const fn scope(&self) -> &PublicationEffectScope {
        match self {
            Self::Claim { scope, .. }
            | Self::Dispatch { scope, .. }
            | Self::MarkUncertain { scope, .. }
            | Self::SucceedSettlement { scope, .. }
            | Self::Reconcile { scope, .. }
            | Self::Reclaim { scope, .. } => scope,
        }
    }
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Claim { .. } => "claim",
            Self::Dispatch { .. } => "dispatch",
            Self::MarkUncertain { .. } => "mark_uncertain",
            Self::SucceedSettlement { .. } => "succeed_settlement",
            Self::Reconcile {
                result: ReconcileOutcome::Succeeded,
                ..
            } => "reconcile_succeeded",
            Self::Reconcile {
                result: ReconcileOutcome::Absent,
                ..
            } => "reconcile_absent",
            Self::Reconcile {
                result: ReconcileOutcome::Inconclusive,
                ..
            } => "reconcile_inconclusive",
            Self::Reclaim { .. } => "reclaim",
        }
    }
    pub(crate) fn fingerprint(&self) -> Result<Digest, PublicationEffectError> {
        if self.id().is_empty()
            || self.id().chars().any(char::is_whitespace)
            || !self.scope().is_well_formed()
        {
            return Err(PublicationEffectError::InvalidAuthorization);
        }
        let intent = crate::publication_effect_intent::encode_intent(self.scope())?;
        let mut fields: Vec<Vec<u8>> = vec![
            self.kind().as_bytes().to_vec(),
            self.id().as_bytes().to_vec(),
            intent,
        ];
        match self {
            Self::Claim { context, .. } => push_context(&mut fields, *context),
            Self::Dispatch {
                context,
                capability,
                ..
            }
            | Self::Reclaim {
                context,
                capability,
                ..
            } => {
                fields.push(capability.as_bytes().to_vec());
                push_context(&mut fields, *context);
            }
            Self::MarkUncertain { capability, .. } => fields.push(capability.as_bytes().to_vec()),
            Self::SucceedSettlement {
                capability,
                evidence,
                ..
            } => {
                fields.push(capability.as_bytes().to_vec());
                fields.push(evidence.as_bytes().to_vec());
            }
            Self::Reconcile {
                capability,
                result,
                evidence,
                ..
            } => {
                fields.push(capability.as_bytes().to_vec());
                fields.push(result_name(*result).as_bytes().to_vec());
                fields.push(evidence.as_bytes().to_vec());
            }
        }
        Ok(hash(
            b"runne.release.publication-effect-command/1\0",
            fields.iter().map(Vec::as_slice),
        ))
    }
}

pub(crate) fn capability_digest(scope: &PublicationEffectScope, command: Digest) -> Digest {
    hash(
        b"runne.release.publication-effect-capability/1\0",
        [
            &scope.authority_instance.as_bytes()[..],
            scope.idempotency_namespace.as_bytes(),
            &scope.generation.to_be_bytes(),
            &command.as_bytes()[..],
        ],
    )
}

pub(crate) const fn result_name(value: ReconcileOutcome) -> &'static str {
    match value {
        ReconcileOutcome::Succeeded => "succeeded",
        ReconcileOutcome::Absent => "absent",
        ReconcileOutcome::Inconclusive => "inconclusive",
    }
}
pub(crate) const fn outcome_state(value: ReconcileOutcome) -> PublicationEffectState {
    match value {
        ReconcileOutcome::Succeeded => PublicationEffectState::ReconciledSucceeded,
        ReconcileOutcome::Absent => PublicationEffectState::ReconciledAbsent,
        ReconcileOutcome::Inconclusive => PublicationEffectState::Blocked,
    }
}
fn push_context(fields: &mut Vec<Vec<u8>>, value: PublicationEffectContext) {
    fields.push(value.observed_at.to_be_bytes().to_vec());
    fields.push(value.revocation_epoch.to_be_bytes().to_vec());
    fields.push(value.allowlist_generation.to_be_bytes().to_vec());
}
fn hash<'a>(domain: &[u8], fields: impl IntoIterator<Item = &'a [u8]>) -> Digest {
    let mut h = Sha256::new();
    h.update(domain);
    for field in fields {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    Digest::from_bytes(h.finalize().into())
}
