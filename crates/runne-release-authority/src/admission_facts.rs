//! Durable scalar facts retained after consuming fixture admission input.

use crate::{
    AuthorityError, CandidateBinding, Digest, StoredStage, VerifiedStagePayload, wire::ReleaseFacts,
};

#[derive(Clone)]
pub struct StoredAdmissionFacts {
    pub(crate) unsigned: Digest,
    manifest: Vec<u8>,
    release: Option<ReleaseFacts>,
}
impl StoredAdmissionFacts {
    pub(crate) fn from_manifest(manifest: &crate::InspectedCanonicalPayload) -> Self {
        Self {
            unsigned: manifest.raw_digest(),
            manifest: manifest.raw().to_vec(),
            release: manifest.release_facts().cloned(),
        }
    }
    pub(crate) fn rc2_projection(&self) -> Option<Rc2ReleaseFactsProjection<'_>> {
        self.release
            .as_ref()
            .map(|release| Rc2ReleaseFactsProjection { release })
    }
    pub(crate) const fn release_facts(&self) -> Option<&ReleaseFacts> {
        self.release.as_ref()
    }
    pub(crate) fn manifest(&self) -> &[u8] {
        &self.manifest
    }
    pub(crate) fn from_durable(
        binding: CandidateBinding,
        unsigned: Digest,
        manifest: Vec<u8>,
        release: ReleaseFacts,
    ) -> Result<Self, AuthorityError> {
        let parsed = crate::InspectedCanonicalPayload::parse(
            crate::CanonicalPayloadKind::UnsignedManifest,
            &manifest,
        )?;
        if parsed.raw_digest() != unsigned
            || binding.release_facts() != Some(unsigned)
            || !parsed.matches_binding(&binding)
            || parsed.release_facts() != Some(&release)
        {
            return Err(AuthorityError::BindingMismatch);
        }
        Ok(Self {
            unsigned,
            manifest,
            release: Some(release),
        })
    }
    pub(crate) fn validate_rc1(
        &self,
        binding: CandidateBinding,
        stage: &VerifiedStagePayload,
    ) -> Result<(), AuthorityError> {
        let approver = stage
            .inspected()
            .rc1_approver()
            .ok_or(AuthorityError::BindingMismatch)?;
        if stage.kind() != crate::CanonicalPayloadKind::Rc1Decision
            || approver.principal != stage.issuer().principal_id()
            || approver.account != stage.issuer().account_id()
            || approver.lane != stage.issuer().lane_id()
            || approver.key != stage.issuer().key_id()
            || approver.signature_profile != stage.issuer().signature_profile_id()
            || !stage.inspected().matches_binding(&binding)
            || stage.inspected().release_facts_digest() != Some(self.unsigned)
            || stage.bootstrap() != binding.bootstrap()
            || !stage.inspected().binds_raw_dag(&crate::wire::RawDag {
                records: Vec::new(),
                inventory: Digest::from_bytes([0; 32]),
                metadata: Digest::from_bytes([0; 32]),
                report: Digest::from_bytes([0; 32]),
                manifest: Digest::from_bytes([0; 32]),
                binding: binding.sha256(),
                unsigned_manifest: self.unsigned,
            })
        {
            return Err(AuthorityError::BindingMismatch);
        }
        Ok(())
    }
    pub(crate) fn validate_rc2(
        &self,
        binding: CandidateBinding,
        rc1: &StoredStage,
        stage: &VerifiedStagePayload,
    ) -> Result<(), AuthorityError> {
        if rc1.bootstrap != binding.bootstrap()
            || stage.kind() != crate::CanonicalPayloadKind::Rc2Authorization
            || stage.bootstrap() != binding.bootstrap()
            || !stage.inspected().matches_binding(&binding)
            || !stage.inspected().binds_raw_dag(&crate::wire::RawDag {
                records: Vec::new(),
                inventory: Digest::from_bytes([0; 32]),
                metadata: Digest::from_bytes([0; 32]),
                report: Digest::from_bytes([0; 32]),
                manifest: Digest::from_bytes([0; 32]),
                binding: binding.sha256(),
                unsigned_manifest: self.unsigned,
            })
        {
            return Err(AuthorityError::BindingMismatch);
        }
        let operations = stage
            .inspected()
            .rc2_operational_identities()
            .ok_or(AuthorityError::BindingMismatch)?;
        let plan = stage
            .inspected()
            .rc2_plan()
            .ok_or(AuthorityError::BindingMismatch)?;
        let facts = self
            .rc2_projection()
            .ok_or(AuthorityError::BindingMismatch)?;
        if !plan
            .artifacts
            .iter()
            .all(|(slot, platform, digest, length)| {
                facts.matches_pre_sign(slot, platform, *digest, *length)
            })
        {
            return Err(AuthorityError::BindingMismatch);
        }
        let mut dimensions = [
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
        ];
        for issuer in [&rc1.root, &rc1.issuer, stage.issuer()] {
            for (set, value) in dimensions.iter_mut().zip([
                issuer.principal_id(),
                issuer.account_id(),
                issuer.lane_id(),
                issuer.key_id(),
                issuer.signature_profile_id(),
            ]) {
                if !set.insert(value) {
                    return Err(AuthorityError::IdentitySeparationViolation);
                }
            }
        }
        for operation in operations {
            for (set, value) in dimensions.iter_mut().zip(operation) {
                if !set.insert(value) {
                    return Err(AuthorityError::IdentitySeparationViolation);
                }
            }
        }
        Ok(())
    }
}

/// Immutable RC1 release-facts view; later RC2 code can only compare against it.
pub struct Rc2ReleaseFactsProjection<'a> {
    release: &'a ReleaseFacts,
}
impl Rc2ReleaseFactsProjection<'_> {
    pub(crate) fn matches_pre_sign(
        &self,
        slot: &str,
        platform: &str,
        digest: Digest,
        length: u64,
    ) -> bool {
        self.release
            .artifacts
            .iter()
            .filter(|artifact| artifact.artifact_slot_id == slot)
            .filter(|artifact| artifact.platform == platform)
            .filter(|artifact| artifact.artifact_sha256.value() == digest)
            .filter(|artifact| artifact.byte_length == length)
            .take(2)
            .count()
            == 1
    }
}
