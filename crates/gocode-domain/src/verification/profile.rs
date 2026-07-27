use crate::verification::identity::*;
use crate::verification::digest::{DigestContract, VerificationDigest};

/// Immutable evaluation profile — builder pattern with validation.
#[derive(Clone, Debug)]
pub struct EvaluationProfile {
    pub profile_id: ProfileID,
    pub plan_id: PlanID,
    pub plan_revision: u64,
    pub deterministic_seed: Option<u64>,
    pub integrity_digest: VerificationDigest,
    pub evidence_layer: String,
    pub harness_digest: VerificationDigest,
}

impl EvaluationProfile {
    pub fn builder() -> ProfileBuilder {
        ProfileBuilder::default()
    }

    fn compute_digest(
        profile_id: ProfileID, plan_id: PlanID, plan_revision: u64,
        seed: Option<u64>, layer: &str, harness: &VerificationDigest,
    ) -> VerificationDigest {
        let contract = DigestContract::new("gocode:evaluation-profile:v1");
        let seed_bytes = seed.map(|s| s.to_be_bytes().to_vec()).unwrap_or_default();
        contract.compute(&[
            profile_id.as_bytes(),
            plan_id.as_bytes(),
            &plan_revision.to_be_bytes(),
            &seed_bytes,
            layer.as_bytes(),
            harness.as_bytes(),
        ])
    }
}

#[derive(Default)]
pub struct ProfileBuilder {
    profile_id: Option<ProfileID>,
    plan_id: Option<PlanID>,
    plan_revision: u64,
    deterministic_seed: Option<u64>,
    evidence_layer: Option<String>,
    harness_digest: Option<VerificationDigest>,
}

impl ProfileBuilder {
    pub fn profile_id(mut self, id: ProfileID) -> Self { self.profile_id = Some(id); self }
    pub fn plan_id(mut self, id: PlanID) -> Self { self.plan_id = Some(id); self }
    pub fn plan_revision(mut self, rev: u64) -> Self { self.plan_revision = rev; self }
    pub fn deterministic_seed(mut self, seed: u64) -> Self { self.deterministic_seed = Some(seed); self }
    pub fn evidence_layer(mut self, layer: &str) -> Self { self.evidence_layer = Some(layer.to_string()); self }
    pub fn harness_digest(mut self, d: VerificationDigest) -> Self { self.harness_digest = Some(d); self }

    pub fn build(self) -> Result<EvaluationProfile, ProfileError> {
        let profile_id = self.profile_id.ok_or(ProfileError::MissingField("profile_id"))?;
        let plan_id = self.plan_id.ok_or(ProfileError::MissingField("plan_id"))?;
        let layer = self.evidence_layer.unwrap_or_else(|| "L0".to_string());
        let harness = self.harness_digest.unwrap_or_else(|| VerificationDigest::from_bytes([0; 32]));
        let integrity_digest = EvaluationProfile::compute_digest(
            profile_id, plan_id, self.plan_revision, self.deterministic_seed, &layer, &harness,
        );
        Ok(EvaluationProfile { profile_id, plan_id, plan_revision: self.plan_revision,
            deterministic_seed: self.deterministic_seed, integrity_digest, evidence_layer: layer, harness_digest: harness })
    }
}

#[derive(Debug)]
pub enum ProfileError { MissingField(&'static str) }

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing required field: {:?}", self)
    }
}
impl std::error::Error for ProfileError {}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test] fn profile_build_minimal() { let p = EvaluationProfile::builder().profile_id(Uuid::now_v7()).plan_id(Uuid::now_v7()).build().unwrap(); assert_eq!(p.plan_revision, 0); }
    #[test] fn profile_digest_stable() { let pid = Uuid::now_v7(); let plan = Uuid::now_v7(); let p1 = EvaluationProfile::builder().profile_id(pid).plan_id(plan).deterministic_seed(42).build().unwrap(); let p2 = EvaluationProfile::builder().profile_id(pid).plan_id(plan).deterministic_seed(42).build().unwrap(); assert_eq!(p1.integrity_digest, p2.integrity_digest); }
    #[test] fn profile_digest_changes_with_seed() { let id = Uuid::now_v7(); let pid = Uuid::now_v7(); let p1 = EvaluationProfile::builder().profile_id(id).plan_id(pid).deterministic_seed(42).build().unwrap(); let p2 = EvaluationProfile::builder().profile_id(id).plan_id(pid).deterministic_seed(43).build().unwrap(); assert_ne!(p1.integrity_digest, p2.integrity_digest); }
    #[test] fn profile_missing_plan_id_rejected() { assert!(EvaluationProfile::builder().profile_id(Uuid::now_v7()).build().is_err()); }
    #[test] fn profile_missing_profile_id_rejected() { assert!(EvaluationProfile::builder().plan_id(Uuid::now_v7()).build().is_err()); }
}
