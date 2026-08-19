use std::collections::BTreeMap;

use crate::store::CommandFingerprint;
use crate::{
    AuthorityError, CandidateBinding, Digest, Mutation, PromotionState, TransactionOutcome,
};

use crate::store_stage_trust::{ThresholdAckDelivery, ThresholdAckTombstone};

#[derive(Clone)]
pub struct Record {
    pub(crate) authority_instance: Digest,
    pub(crate) state: Option<PromotionState>,
    pub(crate) binding: Option<CandidateBinding>,
    pub(crate) admission: Option<crate::FixtureAdmission>,
    pub(crate) admission_facts: Option<crate::admission_facts::StoredAdmissionFacts>,
    pub(crate) rc1: Option<crate::StoredStage>,
    pub(crate) rc2: Option<crate::StoredStage>,
    pub(crate) rc2_effect_authorization: Option<crate::FixtureRc2SigningAuthorization>,
    pub(crate) revision: u64,
    pub(crate) inventory: Option<Digest>,
    pub(crate) metadata: Option<Digest>,
    pub(crate) report: Option<Digest>,
    pub(crate) reservation: Option<StoredVerifySignedReservation>,
    pub(crate) stage_reservation:
        Option<crate::store_stage_reservation::StoredStageTransitionReservation>,
    pub(crate) stage_claims: BTreeMap<String, crate::store_stage_claim::StoredStageClaim>,
    pub(crate) stage_trust: crate::store_stage_trust::StoredStageTrust,
    pub(crate) rc2_evidence_trust: crate::store_rc2_evidence_trust::StoredRc2EvidenceTrust,
    pub(crate) threshold_admission: Option<Digest>,
    pub(crate) threshold_outbox: Option<ThresholdAckDelivery>,
    pub(crate) threshold_ack: Option<ThresholdAckTombstone>,
    pub(crate) publication_manifest: Option<Digest>,
    pub(crate) publication_authorization: Option<Digest>,
    pub(crate) publication_destination: Option<String>,
    pub(crate) publication_channel: Option<String>,
    pub(crate) publication_namespace: Option<String>,
    pub(crate) publication_executor: Option<String>,
    pub(crate) publication_lane: Option<String>,
    pub(crate) publication_workflow: Option<Digest>,
    pub(crate) publication_valid_from: Option<u64>,
    pub(crate) publication_expires_at: Option<u64>,
    pub(crate) publication_revocation_epoch: Option<u64>,
    pub(crate) commands: BTreeMap<String, (CommandFingerprint, TransactionOutcome)>,
    pub(crate) completed_verify: BTreeMap<String, (u64, Digest)>,
    pub(crate) previous_snapshot: Option<Digest>,
    pub(crate) snapshot: Option<crate::PromotionStateSnapshot>,
}
impl Default for Record {
    fn default() -> Self {
        Self {
            authority_instance: Digest::from_bytes([0; 32]),
            state: None,
            binding: None,
            admission: None,
            admission_facts: None,
            rc1: None,
            rc2: None,
            rc2_effect_authorization: None,
            revision: 0,
            inventory: None,
            metadata: None,
            report: None,
            reservation: None,
            stage_reservation: None,
            stage_claims: BTreeMap::new(),
            stage_trust: crate::store_stage_trust::StoredStageTrust::default(),
            rc2_evidence_trust: crate::store_rc2_evidence_trust::StoredRc2EvidenceTrust::default(),
            threshold_admission: None,
            threshold_outbox: None,
            threshold_ack: None,
            publication_manifest: None,
            publication_authorization: None,
            publication_destination: None,
            publication_channel: None,
            publication_namespace: None,
            publication_executor: None,
            publication_lane: None,
            publication_workflow: None,
            publication_valid_from: None,
            publication_expires_at: None,
            publication_revocation_epoch: None,
            commands: BTreeMap::new(),
            completed_verify: BTreeMap::new(),
            previous_snapshot: None,
            snapshot: None,
        }
    }
}
#[derive(Clone)]
pub struct StoredVerifySignedReservation {
    pub(crate) authority_instance: Digest,
    pub(crate) promotion: crate::PromotionId,
    pub(crate) revision: u64,
    pub(crate) authorization: Digest,
    pub(crate) command: String,
    pub(crate) fingerprint: CommandFingerprint,
    pub(crate) commitment: Digest,
    pub(crate) evidence_trust: crate::rc2_evidence_common::EvidenceTrustBinding,
    pub(crate) evidence_expires_at: u64,
}
impl StoredVerifySignedReservation {
    #[allow(clippy::too_many_arguments)] // Exact durable reservation identity is intentionally scalar.
    pub(crate) fn matches(
        &self,
        authority_instance: Digest,
        id: &crate::PromotionId,
        revision: u64,
        authorization: Digest,
        command: &crate::CommandId,
        fingerprint: CommandFingerprint,
        commitment: Digest,
        evidence_trust: crate::rc2_evidence_common::EvidenceTrustBinding,
        evidence_expires_at: u64,
    ) -> bool {
        self.authority_instance == authority_instance
            && self.promotion == *id
            && self.revision == revision
            && self.authorization == authorization
            && self.command == command.as_str()
            && self.fingerprint == fingerprint
            && self.commitment == commitment
            && self.evidence_trust == evidence_trust
            && self.evidence_expires_at == evidence_expires_at
    }
}
pub fn apply(r: &mut Record, mutation: Mutation) -> Result<(), AuthorityError> {
    match mutation {
        Mutation::Ingest { binding, admission } => ingest(r, binding, admission)?,
        Mutation::StartRc1Review {} => {
            simple(r, PromotionState::Rc0Ingested, PromotionState::Rc1Review)?;
        }
        Mutation::QualifyUnsigned { transition } => {
            crate::store_machine_rc2::qualify(r, *transition)?;
        }
        Mutation::FixtureAuthorizeSigning { transition } => {
            crate::store_machine_rc2::authorize_signing(r, *transition)?;
        }
        Mutation::VerifySigned { proof } => verify_signed(r, *proof)?,
        Mutation::StartRc3Review {} => simple(
            r,
            PromotionState::SignedEnvelopesVerified,
            PromotionState::Rc3Review,
        )?,
        Mutation::FixtureAuthorizePublication { bundle } => authorize_publication(r, *bundle)?,
    }
    Ok(())
}
fn ingest(
    r: &mut Record,
    binding: CandidateBinding,
    admission: Box<crate::FixtureAdmission>,
) -> Result<(), AuthorityError> {
    if r.state.is_some() || !binding.is_fixture() || !admission.matches(&binding) {
        return Err(AuthorityError::InvalidTransition);
    }
    r.binding = Some(binding);
    r.admission_facts = Some(admission.stored_facts());
    r.admission = Some(*admission);
    r.state = Some(PromotionState::Rc0Ingested);
    Ok(())
}
fn simple(r: &mut Record, from: PromotionState, to: PromotionState) -> Result<(), AuthorityError> {
    if r.state != Some(from) {
        return Err(AuthorityError::BindingMismatch);
    }
    r.state = Some(to);
    Ok(())
}
fn verify_signed(
    r: &mut Record,
    proof: crate::DurableThresholdProof,
) -> Result<(), AuthorityError> {
    if r.state != Some(PromotionState::SigningAuthorized) {
        return Err(AuthorityError::InvalidTransition);
    }
    let reservation = r
        .reservation
        .as_ref()
        .ok_or(AuthorityError::BindingMismatch)?;
    let authority_instance = proof.authority_instance();
    let (
        promotion,
        revision,
        authorization,
        candidate,
        inventory,
        metadata,
        report,
        commitment,
        admission,
    ) = proof.into_parts();
    if promotion != reservation.promotion
        || authority_instance != reservation.authority_instance
        || revision != r.revision
        || authorization != reservation.authorization
        || commitment != reservation.commitment
        || candidate
            != r.binding
                .ok_or(AuthorityError::BindingMismatch)?
                .candidate()
    {
        return Err(AuthorityError::BindingMismatch);
    }
    if r.rc2_evidence_trust.snapshot()?.binding() != reservation.evidence_trust
        || r.rc2_evidence_trust.now >= reservation.evidence_expires_at
    {
        return Err(AuthorityError::BindingMismatch);
    }
    r.inventory = Some(inventory);
    r.metadata = Some(metadata);
    r.report = Some(report);
    r.threshold_admission = Some(admission);
    r.threshold_outbox = Some(ThresholdAckDelivery::Pending {
        admission,
        revision: r
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::StaleRevision)?,
    });
    r.completed_verify
        .insert(reservation.command.clone(), (revision, commitment));
    r.reservation = None;
    r.state = Some(PromotionState::SignedEnvelopesVerified);
    Ok(())
}
fn authorize_publication(
    r: &mut Record,
    bundle: crate::FixturePublicationBundle,
) -> Result<(), AuthorityError> {
    if r.state != Some(PromotionState::Rc3Review) {
        return Err(AuthorityError::InvalidTransition);
    }
    let (stage, manifest, destination, channel, namespace) = bundle.into_parts();
    let authorization = stage
        .inspected()
        .rc3_raw_bindings()
        .ok_or(AuthorityError::BindingMismatch)?;
    r.publication_manifest = Some(manifest);
    r.publication_authorization = Some(crate::Digest::from_bytes(stage.sha256()));
    r.publication_destination = Some(destination);
    r.publication_channel = Some(channel);
    r.publication_namespace = Some(namespace);
    r.publication_executor = Some(authorization.executor);
    r.publication_lane = Some(authorization.lane);
    r.publication_workflow = Some(authorization.workflow);
    r.publication_valid_from = Some(authorization.valid_from);
    r.publication_expires_at = Some(authorization.expires_at);
    r.publication_revocation_epoch = Some(authorization.revocation_epoch);
    r.stage_reservation = None;
    r.state = Some(PromotionState::PublicationAuthorized);
    Ok(())
}
