//! In-memory fixture promotion-store adapter over shared scalar transitions.

use crate::{
    AuthorityError, CommandId, InMemoryPromotionStore, Mutation, PromotionId, PromotionStore,
    SigningAuthorizedReceipt, StageTransitionStore, TransactionOutcome,
};

impl InMemoryPromotionStore {
    pub(crate) fn rebind_unclaimed_authority(
        &mut self,
        authority_instance: crate::Digest,
    ) -> Result<(), AuthorityError> {
        if !self.rc2_effect_ledger.is_empty() {
            return Err(AuthorityError::BindingMismatch);
        }
        for record in self.entries.values_mut() {
            record.authority_instance = authority_instance;
            if let Some(authorization) = &mut record.rc2_effect_authorization {
                let mut fixture = authorization.fixture();
                fixture.authority_instance = authority_instance;
                *authorization = fixture
                    .signing_authorized()
                    .map_err(|_| AuthorityError::BindingMismatch)?;
            }
        }
        self.authority_instance = authority_instance;
        Ok(())
    }
    /// Replace the fixture's authenticated stage trust snapshot before a raw submission.
    ///
    /// # Errors
    /// Returns an error when the promotion has no initialized fixture record.
    pub fn set_stage_trust(
        &mut self,
        id: &PromotionId,
        trust: crate::StageTrustFixture,
    ) -> Result<(), AuthorityError> {
        self.entries
            .get_mut(id)
            .ok_or(AuthorityError::InvalidTransition)?
            .stage_trust = crate::store_stage_trust::StoredStageTrust {
            now: trust.now,
            utc: trust.utc,
            root_epoch: trust.root_epoch,
            role_floor: trust.role_floor,
        };
        Ok(())
    }
    /// Persist the complete fixture verification trust root before raw RC2 evidence admission.
    ///
    /// # Errors
    /// Returns an error when the fixture promotion is absent.
    pub fn set_rc2_evidence_trust_snapshot(
        &mut self,
        id: &PromotionId,
        trust: &crate::FixtureEvidenceTrustState,
    ) -> Result<(), AuthorityError> {
        let binding = trust.binding();
        let record = self
            .entries
            .get_mut(id)
            .ok_or(AuthorityError::InvalidTransition)?;
        if !record.rc2_evidence_trust.registrations.is_empty()
            && (binding.generation
                != record
                    .rc2_evidence_trust
                    .generation
                    .checked_add(1)
                    .ok_or(AuthorityError::BindingMismatch)?
                || trust.registrations().is_empty())
        {
            return Err(AuthorityError::BindingMismatch);
        }
        record.rc2_evidence_trust = crate::store_rc2_evidence_trust::StoredRc2EvidenceTrust {
            now: binding.now,
            revocation_epoch: binding.revocation_epoch,
            generation: binding.generation,
            registrations: trust.registrations().to_vec(),
        };
        Ok(())
    }
    /// Return a durable completed command outcome without reconstructing authority proof.
    ///
    /// # Errors
    /// Returns an error when no durable outcome exists for this exact command.
    pub fn completed_outcome(
        &self,
        id: &PromotionId,
        expected: u64,
        command: &CommandId,
        bundle: &crate::FixturePrevalidatedSignedBundle,
    ) -> Result<TransactionOutcome, AuthorityError> {
        crate::store_transition::completed(
            self.entries
                .get(id)
                .ok_or(AuthorityError::InvalidTransition)?,
            id,
            expected,
            command,
            bundle,
        )
    }
    /// # Errors
    /// Returns an error when the promotion or threshold backend is unavailable.
    pub fn acknowledge_threshold_completion(
        &mut self,
        id: &PromotionId,
        expected: u64,
        command: CommandId,
        context: &dyn crate::ThresholdVerificationContext,
    ) -> Result<TransactionOutcome, AuthorityError> {
        let record = self
            .entries
            .get_mut(id)
            .ok_or(AuthorityError::InvalidTransition)?;
        if let Some(tombstone) = &record.threshold_ack {
            let fingerprint = crate::store_command::threshold_ack_fingerprint(
                id,
                expected,
                &command,
                tombstone.admission,
            );
            return (tombstone.claim_revision == expected
                && tombstone.command == command.as_str()
                && tombstone.fingerprint == fingerprint)
                .then(|| tombstone.outcome.clone())
                .ok_or(AuthorityError::CommandReplayDiverged);
        }
        let (claim, fingerprint) =
            crate::store_transition::begin_ack(record, id, expected, &command)?;
        let proof =
            context.acknowledge_or_recover(&crate::ThresholdAckRequest { claim: &claim })?;
        crate::store_transition::settle_ack(record, id, command, claim, proof, fingerprint)
    }
}

impl PromotionStore for InMemoryPromotionStore {
    fn transact(
        &mut self,
        id: &PromotionId,
        expected: u64,
        command: CommandId,
        mutation: Mutation,
    ) -> Result<TransactionOutcome, AuthorityError> {
        crate::store_command::require_canonical(&command)?;
        let authority_instance = self.authority_instance;
        let record =
            self.entries
                .entry(id.clone())
                .or_insert_with(|| crate::store_machine::Record {
                    authority_instance,
                    ..Default::default()
                });
        if record.authority_instance != authority_instance {
            return Err(AuthorityError::BindingMismatch);
        }
        crate::store_transition::transact(record, id, expected, command, mutation)
    }
    fn reserve_verify_signed(
        &mut self,
        id: &PromotionId,
        expected: u64,
        command: CommandId,
        bundle: &crate::FixturePrevalidatedSignedBundle,
    ) -> Result<SigningAuthorizedReceipt, AuthorityError> {
        crate::store_transition_reserve::reserve(
            self.entries
                .get_mut(id)
                .ok_or(AuthorityError::InvalidTransition)?,
            &mut self.rc2_effect_ledger,
            id,
            expected,
            command,
            bundle,
        )
    }
}

impl StageTransitionStore for InMemoryPromotionStore {
    fn verify_and_commit_stage_transition(
        &mut self,
        request: crate::store::RawStageTransitionRequest<'_>,
    ) -> Result<TransactionOutcome, AuthorityError> {
        let crate::store::RawStageTransitionRequest {
            promotion: id,
            expected_revision: expected,
            command,
            kind,
            bytes,
            expected_sha256,
            bootstrap,
            publication_manifest,
        } = request;
        crate::rc3_v2_admission::reject_legacy_fixture_ingress(kind)?;
        let mut record = self
            .entries
            .get(id)
            .cloned()
            .ok_or(AuthorityError::InvalidTransition)?;
        let reservation = crate::store_stage_reservation::reserve(
            &mut record,
            id,
            expected,
            command.clone(),
            kind,
        )?;
        let transition = {
            let context = crate::store_stage_context::RecordStageContext::new(&mut record);
            let envelope = gocode_project_owner_authority::verify_stage_envelope_for_transition(
                bytes,
                expected_sha256,
                bootstrap,
                &context,
                reservation,
            )
            .map_err(|_| {
                if kind == gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization
                    && record.state == Some(crate::PromotionState::PublicationAuthorized)
                {
                    AuthorityError::CommandReplayDiverged
                } else {
                    AuthorityError::BindingMismatch
                }
            })?;
            crate::inspect_verified_stage_envelope(envelope)?
        };
        let transition = {
            let context = crate::store_stage_context::RecordStageContext::new(&mut record);
            transition.revalidate(&context)?
        };
        if kind == gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization {
            let manifest = publication_manifest.ok_or(AuthorityError::BindingMismatch)?;
            let fingerprint = crate::FixturePublicationBundle::replay_fingerprint(
                &record,
                manifest,
                &transition,
                expected,
                &command,
            )?;
            if let Some((known, outcome)) = record.commands.get(command.as_str()) {
                return (*known == fingerprint)
                    .then(|| outcome.clone())
                    .ok_or(AuthorityError::CommandReplayDiverged);
            }
        }
        let mutation = if kind == gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization
        {
            crate::store_stage_reservation::publication_mutation(
                &record,
                publication_manifest.ok_or(AuthorityError::BindingMismatch)?,
                transition,
            )?
        } else {
            crate::store_stage_reservation::mutation(transition)?
        };
        let claim_command = command.clone();
        let outcome = crate::store_transition::transact_bound_stage(
            &mut record,
            id,
            expected,
            command,
            mutation,
        )?;
        let claim = record
            .stage_claims
            .values()
            .find(|claim| claim.promotion == id.0 && claim.command == claim_command.as_str())
            .cloned()
            .ok_or(AuthorityError::BindingMismatch)?;
        if let Some(existing) = self.stage_claims.get(&claim.nonce)
            && existing != &claim
        {
            return Err(AuthorityError::BindingMismatch);
        }
        self.stage_claims.insert(claim.nonce.clone(), claim);
        self.entries.insert(id.clone(), record);
        Ok(outcome)
    }
}
