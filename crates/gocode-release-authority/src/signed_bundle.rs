//! Move-only RC2 post-sign DAG prevalidation.

use crate::{
    AuthorityError, CanonicalPayloadKind, Digest, FixtureVerifiedNativeEvidence,
    FixtureVerifiedSigningEffect, FixtureVerifiedSigningReview,
    FixtureVerifiedUpdateMetadataIssuance, InspectedCanonicalPayload,
};
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;

/// Exact structurally and natively verified RC2 payload DAG, not an authority capability.
#[derive(Debug, Eq, PartialEq)]
pub struct FixturePrevalidatedSignedBundle {
    authority_instance: Digest,
    candidate: Digest,
    authorization: Digest,
    inventory: Digest,
    metadata: Digest,
    report: Digest,
    records: [Digest; 3],
    effects: [Digest; 3],
    native: [Digest; 3],
    review: Digest,
    issuance: Digest,
    evidence_trust: crate::rc2_evidence_common::EvidenceTrustBinding,
    evidence_expires_at: u64,
    authorization_valid_from: u64,
    authorization_expires_at: u64,
    authorization_epoch: u64,
    evidence: crate::threshold_context::ThresholdMetadataEvidence,
    pub(crate) effect_closure: RefCell<Option<crate::rc2_effect_lease::FixtureRc2EffectClosure>>,
}

impl FixturePrevalidatedSignedBundle {
    /// Validate the exact five-payload DAG before any threshold backend operation.
    ///
    /// # Errors
    /// Returns an error for a missing, substituted, unordered, or RC2-unbound payload.
    #[allow(clippy::too_many_lines)] // Atomic closure keeps all pre-threshold bindings adjacent.
    #[allow(clippy::needless_pass_by_value)] // Consumes opaque reviewer and issuer handles.
    pub(crate) fn prevalidate(
        authority_instance: Digest,
        payloads: &[InspectedCanonicalPayload],
        effects: [FixtureVerifiedSigningEffect; 3],
        evidence: [FixtureVerifiedNativeEvidence; 3],
        review: FixtureVerifiedSigningReview,
        issuance: FixtureVerifiedUpdateMetadataIssuance,
        authorization: &InspectedCanonicalPayload,
    ) -> Result<Self, AuthorityError> {
        let [
            linux_appimage_evidence,
            linux_deb_evidence,
            windows_evidence,
        ] = evidence;
        let [linux_appimage_effect, linux_deb_effect, windows_effect] = effects;
        let evidence_trust = linux_appimage_effect.trust;
        let exact = |kind| {
            payloads
                .iter()
                .filter(|item| item.kind() == kind)
                .collect::<Vec<_>>()
        };
        let records = exact(CanonicalPayloadKind::ArtifactRecord);
        let inventory = exact(CanonicalPayloadKind::Inventory);
        let metadata = exact(CanonicalPayloadKind::ThresholdMetadata);
        let report = exact(CanonicalPayloadKind::VerificationReport);
        let manifest = exact(CanonicalPayloadKind::UnsignedManifest);
        let plan = authorization
            .rc2_plan()
            .ok_or(AuthorityError::BindingMismatch)?;
        let record_slots = records
            .iter()
            .map(|record| record.artifact_record().map(|parts| parts.artifact_slot_id))
            .collect::<Option<Vec<_>>>()
            .ok_or(AuthorityError::BindingMismatch)?;
        if authorization.kind() != CanonicalPayloadKind::Rc2Authorization
            || payloads.len() != 7
            || records.len() != 3
            || records
                .iter()
                .map(|item| item.artifact_platform())
                .collect::<Vec<_>>()
                != vec![Some("linux"), Some("linux"), Some("windows")]
            || inventory.len() != 1
            || metadata.len() != 1
            || report.len() != 1
            || manifest.len() != 1
            || inventory[0].candidate_digest() != Some(plan.candidate)
            || records
                .iter()
                .zip([
                    (&linux_appimage_evidence, &linux_appimage_effect),
                    (&linux_deb_evidence, &linux_deb_effect),
                    (&windows_evidence, &windows_effect),
                ])
                .any(|(record, (verified, effect))| !verified.matches(record, effect))
            || records
                .iter()
                .zip(plan.artifacts.iter())
                .any(|(raw, expected)| {
                    let Some(record) = raw.artifact_record() else {
                        return true;
                    };
                    let (slot, platform, pre_sign_digest, pre_sign_length) = expected;
                    record.artifact_slot_id != *slot
                        || record.platform != *platform
                        || record.candidate != plan.candidate
                        || record.artifact_length == 0
                        || record.authorization != Digest::from_bytes(authorization.sha256())
                        || record.workflow != plan.workflow
                        || record.signer != plan.signer
                        || record.runner != plan.runner
                        || record.effect_namespace != plan.effect_namespace
                        || record.effect_generation != plan.effect_generation
                        || record.operation != "native_sign"
                        || record.pre_sign_digest != *pre_sign_digest
                        || record.pre_sign_length != *pre_sign_length
                })
            || [&linux_appimage_effect, &linux_deb_effect, &windows_effect]
                .into_iter()
                .any(|effect| {
                    effect.trust != evidence_trust || effect.expires_at <= evidence_trust.now
                })
            || [
                &linux_appimage_evidence,
                &linux_deb_evidence,
                &windows_evidence,
            ]
            .into_iter()
            .any(|native| native.trust != evidence_trust || native.expires_at <= evidence_trust.now)
            || review.trust != evidence_trust
            || issuance.trust != evidence_trust
            || review.expires_at <= evidence_trust.now
            || issuance.expires_at <= evidence_trust.now
            || plan.valid_from > evidence_trust.now
            || plan.expires_at <= evidence_trust.now
            || plan.revocation_epoch != evidence_trust.revocation_epoch
        {
            return Err(AuthorityError::BindingMismatch);
        }
        let dag = crate::wire::RawDag {
            records: records.iter().map(|item| item.raw_digest()).collect(),
            inventory: inventory[0].raw_digest(),
            metadata: metadata[0].raw_digest(),
            report: report[0].raw_digest(),
            manifest: Digest::from_bytes([0; 32]),
            binding: Digest::from_bytes([0; 32]),
            unsigned_manifest: Digest::from_bytes([0; 32]),
        };
        let metadata_parts = metadata[0]
            .threshold_metadata()
            .ok_or(AuthorityError::BindingMismatch)?;
        if metadata_parts.candidate != plan.candidate
            || metadata_parts.inventory != dag.inventory
            || !crate::threshold_target_binding::matches(&metadata_parts, manifest[0], &records)
        {
            return Err(AuthorityError::BindingMismatch);
        }
        let metadata_evidence = crate::threshold_metadata_evidence::from_parts(metadata_parts);
        if !inventory[0].binds_raw_dag(&dag)
            || !metadata[0].binds_raw_dag(&dag)
            || !report[0].binds_raw_dag(&dag)
            || metadata[0].candidate_digest() != Some(plan.candidate)
        {
            return Err(AuthorityError::BindingMismatch);
        }
        if review.authorization != Digest::from_bytes(authorization.sha256())
            || review.inventory != dag.inventory
            || issuance.metadata != dag.metadata
            || review.native
                != std::array::from_fn(|index| {
                    (
                        record_slots[index].clone(),
                        [
                            linux_appimage_evidence.digest,
                            linux_deb_evidence.digest,
                            windows_evidence.digest,
                        ][index],
                    )
                })
        {
            return Err(AuthorityError::BindingMismatch);
        }
        Ok(Self {
            authority_instance,
            candidate: plan.candidate,
            authorization: Digest::from_bytes(authorization.sha256()),
            inventory: dag.inventory,
            metadata: dag.metadata,
            report: dag.report,
            records: [
                records[0].raw_digest(),
                records[1].raw_digest(),
                records[2].raw_digest(),
            ],
            effects: [
                linux_appimage_effect.digest,
                linux_deb_effect.digest,
                windows_effect.digest,
            ],
            native: [
                linux_appimage_evidence.digest,
                linux_deb_evidence.digest,
                windows_evidence.digest,
            ],
            review: review.digest,
            issuance: issuance.digest,
            evidence_trust,
            evidence_expires_at: [
                linux_appimage_effect.expires_at,
                linux_deb_effect.expires_at,
                windows_effect.expires_at,
                linux_appimage_evidence.expires_at,
                linux_deb_evidence.expires_at,
                windows_evidence.expires_at,
                review.expires_at,
                issuance.expires_at,
            ]
            .into_iter()
            .min()
            .ok_or(AuthorityError::BindingMismatch)?,
            authorization_valid_from: plan.valid_from,
            authorization_expires_at: plan.expires_at,
            authorization_epoch: plan.revocation_epoch,
            evidence: metadata_evidence,
            effect_closure: RefCell::new(None),
        })
    }

    pub(crate) const fn candidate(&self) -> Digest {
        self.candidate
    }
    pub(crate) const fn authority_instance(&self) -> Digest {
        self.authority_instance
    }
    pub(crate) const fn authorization(&self) -> Digest {
        self.authorization
    }
    pub(crate) const fn inventory(&self) -> Digest {
        self.inventory
    }
    pub(crate) const fn metadata(&self) -> Digest {
        self.metadata
    }
    pub(crate) const fn report(&self) -> Digest {
        self.report
    }
    pub(crate) const fn evidence(&self) -> &crate::threshold_context::ThresholdMetadataEvidence {
        &self.evidence
    }
    pub(crate) const fn evidence_trust(&self) -> crate::rc2_evidence_common::EvidenceTrustBinding {
        self.evidence_trust
    }
    pub(crate) const fn evidence_expires_at(&self) -> u64 {
        self.evidence_expires_at
    }
    pub(crate) const fn authorization_valid_from(&self) -> u64 {
        self.authorization_valid_from
    }
    pub(crate) const fn authorization_expires_at(&self) -> u64 {
        self.authorization_expires_at
    }
    pub(crate) const fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch
    }
    pub(crate) fn commitment(&self) -> Digest {
        let mut transcript = b"gocode.release.prevalidated-signed-bundle/1\0".to_vec();
        for digest in [
            self.authority_instance,
            self.candidate,
            self.authorization,
            self.inventory,
            self.metadata,
            self.report,
        ]
        .into_iter()
        .chain(self.records)
        .chain(self.effects)
        .chain(self.native)
        .chain([self.review, self.issuance])
        {
            transcript.extend_from_slice(&32_u64.to_be_bytes());
            transcript.extend_from_slice(&digest.as_bytes());
        }
        Digest::from_bytes(Sha256::digest(transcript).into())
    }
}
