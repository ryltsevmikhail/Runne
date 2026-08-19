use super::rc3_v2_models::{Authorization, FinalReview, HumanArtifacts, Identity, Manifest};

/// Exact five-dimensional identity fact retained from a validated RC3 leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityFacts([String; 5]);
impl IdentityFacts {
    /// Return all dimensions in principal/account/lane/key/signature-profile order.
    #[must_use]
    pub fn dimensions(&self) -> [&str; 5] {
        self.0.each_ref().map(String::as_str)
    }
}

/// Closed named human artifact digest set retained from a validated RC3 leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanArtifactFacts(pub [String; 6]);

/// All immutable manifest bindings required by the RC3 graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestFacts {
    pub candidate: String,
    pub inventory: String,
    pub report: String,
    pub metadata: String,
    pub public_artifacts: [(String, String, String, String, u64, String); 3],
    pub human: HumanArtifactFacts,
    pub app_version: String,
    pub release_sequence: u64,
    pub bundle_identity: String,
    pub destination: String,
    pub channel_policy: String,
    pub channel: String,
    pub rollback_policy: String,
    pub rollout_policy: String,
    pub effect_scope: String,
}

/// All immutable final-review bindings required by the RC3 graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewFacts {
    pub candidate: String,
    pub manifest: String,
    pub inventory: String,
    pub report: String,
    pub metadata: String,
    pub human: HumanArtifactFacts,
    pub allowlist: String,
    pub allowlist_generation: u64,
    pub destination: String,
    pub channel: String,
    pub effect_scope: String,
    pub reviewer: IdentityFacts,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
}

/// All immutable authorization bindings required by the RC3 graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationFacts {
    pub candidate: String,
    pub manifest: String,
    pub final_review: String,
    pub allowlist: String,
    pub allowlist_generation: u64,
    pub inventory: String,
    pub report: String,
    pub metadata: String,
    pub destination: String,
    pub channel: String,
    pub effect_scope: String,
    pub authorizer: IdentityFacts,
    pub executor: IdentityFacts,
    pub executable: String,
    pub workflow: String,
    pub namespace: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub self_execution_policy: String,
}

/// Typed facts that only canonical validation can construct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Facts {
    /// Closed publication-manifest bindings.
    Manifest(Box<ManifestFacts>),
    /// Closed final-review bindings.
    FinalReview(Box<ReviewFacts>),
    /// Closed publication-authorization bindings.
    Authorization(Box<AuthorizationFacts>),
}

pub fn manifest(v: &Manifest) -> Facts {
    Facts::Manifest(Box::new(ManifestFacts {
        candidate: v.candidate_sha256.clone(),
        inventory: v.inventory_sha256.clone(),
        report: v.report_sha256.clone(),
        metadata: v.metadata_set_sha256.clone(),
        public_artifacts: std::array::from_fn(|i| {
            let x = &v.public_artifacts[i];
            (
                x.artifact_slot_id.clone(),
                x.platform.clone(),
                x.architecture.clone(),
                x.artifact_sha256.clone(),
                x.byte_length,
                x.checksum_sha256.clone(),
            )
        }),
        human: human(&v.human_artifacts),
        app_version: v.app_version.clone(),
        release_sequence: v.release_sequence,
        bundle_identity: v.bundle_identity.clone(),
        destination: v.destination.clone(),
        channel_policy: v.channel_policy_id.clone(),
        channel: v.channel.clone(),
        rollback_policy: v.rollback_policy_sha256.clone(),
        rollout_policy: v.rollout_policy_sha256.clone(),
        effect_scope: v.effect_scope_sha256.clone(),
    }))
}
pub fn review(v: &FinalReview) -> Facts {
    Facts::FinalReview(Box::new(ReviewFacts {
        candidate: v.candidate_sha256.clone(),
        manifest: v.publication_manifest_sha256.clone(),
        inventory: v.inventory_sha256.clone(),
        report: v.report_sha256.clone(),
        metadata: v.metadata_set_sha256.clone(),
        human: human(&v.human_artifacts),
        allowlist: v.allowlist_sha256.clone(),
        allowlist_generation: v.allowlist_generation,
        destination: v.destination.clone(),
        channel: v.channel.clone(),
        effect_scope: v.effect_scope_sha256.clone(),
        reviewer: identity(&v.reviewer),
        valid_from: v.valid_from,
        expires_at: v.expires_at,
        revocation_epoch: v.revocation_epoch,
    }))
}
pub fn authorization(v: &Authorization) -> Facts {
    Facts::Authorization(Box::new(AuthorizationFacts {
        candidate: v.candidate_sha256.clone(),
        manifest: v.publication_manifest_sha256.clone(),
        final_review: v.final_review_sha256.clone(),
        allowlist: v.allowlist_sha256.clone(),
        allowlist_generation: v.allowlist_generation,
        inventory: v.inventory_sha256.clone(),
        report: v.report_sha256.clone(),
        metadata: v.metadata_set_sha256.clone(),
        destination: v.destination.clone(),
        channel: v.channel.clone(),
        effect_scope: v.effect_scope_sha256.clone(),
        authorizer: identity(&v.authorizer),
        executor: identity(&v.executor),
        executable: v.executable_sha256.clone(),
        workflow: v.workflow_sha256.clone(),
        namespace: v.idempotency_namespace.clone(),
        valid_from: v.valid_from,
        expires_at: v.expires_at,
        revocation_epoch: v.revocation_epoch,
        self_execution_policy: v.self_execution_policy_sha256.clone(),
    }))
}
fn human(v: &HumanArtifacts) -> HumanArtifactFacts {
    HumanArtifactFacts([
        v.release_notes.clone(),
        v.changelog.clone(),
        v.compatibility_support.clone(),
        v.provenance.clone(),
        v.sbom.clone(),
        v.checksums.clone(),
    ])
}
fn identity(v: &Identity) -> IdentityFacts {
    IdentityFacts([
        v.principal.clone(),
        v.account.clone(),
        v.lane.clone(),
        v.key.clone(),
        v.signature_profile.clone(),
    ])
}
