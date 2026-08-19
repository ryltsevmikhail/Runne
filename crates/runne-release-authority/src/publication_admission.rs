//! Fixture-only RC3 publication admission bound to the exact verified post-sign DAG.

use crate::{
    AuthorityError, CanonicalPayloadKind, InspectedCanonicalPayload, VerifiedStagePayload,
};

/// Opaque fixture-only RC3 input; raw manifests and stage DTOs cannot replace it.
#[derive(Debug, Eq, PartialEq)]
pub struct FixturePublicationBundle {
    promotion: crate::PromotionId,
    revision: u64,
    stage: VerifiedStagePayload,
    manifest: crate::Digest,
    destination: String,
    channel: String,
    namespace: String,
    stage_admission_fingerprint: [u8; 32],
}

impl FixturePublicationBundle {
    pub(crate) fn replay_fingerprint(
        record: &crate::store_machine::Record,
        manifest: &InspectedCanonicalPayload,
        transition: &crate::VerifiedStageTransition,
        expected: u64,
        command: &crate::CommandId,
    ) -> Result<crate::store::CommandFingerprint, AuthorityError> {
        let authorization = validate(record, manifest, transition.inspected())?;
        let claim = record
            .stage_claims
            .values()
            .find(|claim| {
                claim.revision == expected
                    && claim.command == command.as_str()
                    && claim.kind
                        == runne_promotion_contracts::CanonicalPayloadKind::Rc3Authorization
            })
            .ok_or(AuthorityError::CommandReplayDiverged)?;
        Ok(crate::store_command::publication_stage_command_fingerprint(
            expected,
            manifest.raw_digest(),
            &authorization.destination,
            &authorization.channel,
            crate::store_stage_claim::stored_command_fingerprint(claim),
        ))
    }
    pub(crate) fn command_commitment(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.revision,
            self.manifest.to_hex(),
            self.destination,
            self.channel,
            crate::threshold_fixture_wire::hex(&self.stage_admission_fingerprint),
        )
    }
    /// Bind the verified RC3 envelope to the exact signed-envelope DAG and publication manifest.
    ///
    /// # Errors
    /// Returns an error unless every signed and publication reference is exact.
    pub(crate) fn from_transition(
        record: &crate::store_machine::Record,
        manifest: &InspectedCanonicalPayload,
        transition: crate::VerifiedStageTransition,
    ) -> Result<Self, AuthorityError> {
        let stage_admission_fingerprint = transition.command_fingerprint();
        let (stage, _, revalidated) = transition.into_parts();
        if !revalidated || record.state != Some(crate::PromotionState::Rc3Review) {
            return Err(AuthorityError::BindingMismatch);
        }
        let authorization = validate(record, manifest, stage.inspected())?;
        let namespace = authorization.idempotency_namespace;
        Ok(Self {
            promotion: record
                .stage_reservation
                .as_ref()
                .map(|reservation| reservation.promotion.clone())
                .ok_or(AuthorityError::BindingMismatch)?,
            revision: record.revision,
            stage,
            manifest: manifest.raw_digest(),
            destination: authorization.destination,
            channel: authorization.channel,
            namespace,
            stage_admission_fingerprint,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (VerifiedStagePayload, crate::Digest, String, String, String) {
        (
            self.stage,
            self.manifest,
            self.destination,
            self.channel,
            self.namespace,
        )
    }
    pub(crate) const fn promotion(&self) -> &crate::PromotionId {
        &self.promotion
    }
    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }
}

fn validate(
    record: &crate::store_machine::Record,
    manifest: &InspectedCanonicalPayload,
    stage: &InspectedCanonicalPayload,
) -> Result<crate::wire::semantics::Rc3RawBindings, AuthorityError> {
    let binding = record.binding.ok_or(AuthorityError::BindingMismatch)?;
    let inventory = record.inventory.ok_or(AuthorityError::BindingMismatch)?;
    let metadata = record.metadata.ok_or(AuthorityError::BindingMismatch)?;
    let report = record.report.ok_or(AuthorityError::BindingMismatch)?;
    let publication = manifest
        .publication()
        .ok_or(AuthorityError::BindingMismatch)?;
    let authorization = stage
        .rc3_raw_bindings()
        .ok_or(AuthorityError::BindingMismatch)?;
    if manifest.kind() != CanonicalPayloadKind::PublicationManifest
        || stage.kind() != CanonicalPayloadKind::Rc3Authorization
        || publication.candidate != binding.candidate()
        || publication.inventory != inventory
        || publication.metadata != metadata
        || publication.report != report
        || authorization.inventory != inventory
        || authorization.report != report
        || authorization.manifest != manifest.raw_digest()
        || authorization.channel != publication.channel
        || authorization.destination != publication.destination
        || !manifest.binds_raw_dag(&crate::wire::RawDag {
            records: Vec::new(),
            inventory,
            metadata,
            report,
            manifest: crate::Digest::from_bytes([0; 32]),
            binding: binding.sha256(),
            unsigned_manifest: crate::Digest::from_bytes([0; 32]),
        })
        || !stage.binds_raw_dag(&crate::wire::RawDag {
            records: Vec::new(),
            inventory,
            metadata,
            report,
            manifest: manifest.raw_digest(),
            binding: binding.sha256(),
            unsigned_manifest: crate::Digest::from_bytes([0; 32]),
        })
    {
        return Err(AuthorityError::BindingMismatch);
    }
    Ok(authorization)
}
