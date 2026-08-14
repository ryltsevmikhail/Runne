//! Durable reservation of a single owner-verified stage transition.

use crate::{AuthorityError, CommandId, PromotionId, PromotionState};

#[derive(Clone)]
pub struct StoredStageTransitionReservation {
    pub(crate) promotion: PromotionId,
    pub(crate) revision: u64,
    pub(crate) command: String,
    pub(crate) kind: gocode_promotion_contracts::CanonicalPayloadKind,
    pub(crate) fingerprint: [u8; 32],
}

impl StoredStageTransitionReservation {
    pub(crate) fn matches(
        &self,
        id: &PromotionId,
        revision: u64,
        command: &CommandId,
        kind: gocode_promotion_contracts::CanonicalPayloadKind,
        fingerprint: [u8; 32],
    ) -> bool {
        self.promotion == *id
            && self.revision == revision
            && self.command == command.as_str()
            && self.kind == kind
            && self.fingerprint == fingerprint
    }
}

pub fn reserve(
    record: &mut crate::store_machine::Record,
    id: &PromotionId,
    expected: u64,
    command: CommandId,
    kind: gocode_promotion_contracts::CanonicalPayloadKind,
) -> Result<gocode_promotion_contracts::StageTransitionReservation, AuthorityError> {
    if !gocode_promotion_contracts::canonical_id(&id.0) || !command.is_canonical() {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    let fingerprint =
        crate::store_command::stage_reservation_fingerprint(id, expected, command.as_str(), kind);
    if record.commands.contains_key(command.as_str()) {
        return gocode_promotion_contracts::StageTransitionReservation::new(
            id.0.clone(),
            expected,
            command.into_inner(),
            kind,
            fingerprint,
        )
        .map_err(|_| AuthorityError::BindingMismatch);
    }
    if kind == gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization
        && record.state == Some(PromotionState::PublicationAuthorized)
    {
        return gocode_promotion_contracts::StageTransitionReservation::new(
            id.0.clone(),
            expected,
            command.into_inner(),
            kind,
            fingerprint,
        )
        .map_err(|_| AuthorityError::BindingMismatch);
    }
    let expected_state = match kind {
        gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision => PromotionState::Rc1Review,
        gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => {
            PromotionState::QualifiedUnsigned
        }
        gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => {
            PromotionState::Rc3Review
        }
    };
    if record.revision != expected {
        return Err(AuthorityError::StaleRevision);
    }
    if record.state != Some(expected_state) {
        return Err(AuthorityError::InvalidTransition);
    }
    if let Some(existing) = &record.stage_reservation {
        return existing
            .matches(id, expected, &command, kind, fingerprint)
            .then(|| {
                gocode_promotion_contracts::StageTransitionReservation::new(
                    id.0.clone(),
                    expected,
                    command.into_inner(),
                    kind,
                    fingerprint,
                )
                .expect("store identifiers are canonical")
            })
            .ok_or(AuthorityError::CommandReplayDiverged);
    }
    record.stage_reservation = Some(StoredStageTransitionReservation {
        promotion: id.clone(),
        revision: expected,
        command: command.as_str().into(),
        kind,
        fingerprint,
    });
    gocode_promotion_contracts::StageTransitionReservation::new(
        id.0.clone(),
        expected,
        command.into_inner(),
        kind,
        fingerprint,
    )
    .map_err(|_| AuthorityError::BindingMismatch)
}

pub fn mutation(
    transition: crate::VerifiedStageTransition,
) -> Result<crate::Mutation, AuthorityError> {
    match transition.stage_kind() {
        crate::CanonicalPayloadKind::Rc1Decision => Ok(crate::Mutation::QualifyUnsigned {
            transition: Box::new(transition),
        }),
        crate::CanonicalPayloadKind::Rc2Authorization => {
            Ok(crate::Mutation::FixtureAuthorizeSigning {
                transition: Box::new(transition),
            })
        }
        _ => Err(AuthorityError::BindingMismatch),
    }
}

pub fn publication_mutation(
    record: &crate::store_machine::Record,
    manifest: &crate::InspectedCanonicalPayload,
    transition: crate::VerifiedStageTransition,
) -> Result<crate::Mutation, AuthorityError> {
    Ok(crate::Mutation::FixtureAuthorizePublication {
        bundle: Box::new(crate::FixturePublicationBundle::from_transition(
            record, manifest, transition,
        )?),
    })
}
