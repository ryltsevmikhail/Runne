use super::{InspectedCanonicalPayload, Payload};
#[path = "semantics_rc2_identity.rs"]
mod rc2_identity;
pub use rc2_identity::Rc3AuthorizationParts;
#[cfg(any(test, feature = "fixture-only"))]
use rc2_identity::owned_parts;
use rc2_identity::parts;
#[cfg(any(test, feature = "fixture-only"))]
#[path = "semantics_threshold.rs"]
mod threshold;
#[cfg(any(test, feature = "fixture-only"))]
pub use threshold::ThresholdMetadataParts;
#[cfg(any(test, feature = "fixture-only"))]
pub struct ArtifactRecordParts {
    pub artifact_slot_id: String,
    pub platform: String,
    pub candidate: crate::Digest,
    pub artifact: crate::Digest,
    pub artifact_length: u64,
    pub authorization: crate::Digest,
    pub workflow: crate::Digest,
    pub signer: [String; 5],
    pub runner: [String; 5],
    pub effect_namespace: String,
    pub effect_generation: u64,
    pub operation: String,
    pub pre_sign_digest: crate::Digest,
    pub pre_sign_length: u64,
    pub attestations: [crate::Digest; 10],
}
#[cfg(any(test, feature = "fixture-only"))]
pub struct Rc2PlanParts {
    pub candidate: crate::Digest,
    pub workflow: crate::Digest,
    pub signer: [String; 5],
    pub runner: [String; 5],
    pub effect_namespace: String,
    pub effect_generation: u64,
    pub artifacts: [(String, String, crate::Digest, u64); 3],
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
}
#[cfg(any(test, feature = "fixture-only"))]
pub struct PublicationParts {
    pub candidate: crate::Digest,
    pub inventory: crate::Digest,
    pub metadata: crate::Digest,
    pub report: crate::Digest,
    pub channel: String,
    pub destination: String,
}
#[cfg(any(test, feature = "fixture-only"))]
pub struct Rc3RawBindings {
    pub inventory: crate::Digest,
    pub report: crate::Digest,
    pub manifest: crate::Digest,
    pub channel: String,
    pub destination: String,
    pub idempotency_namespace: String,
    pub executor: String,
    pub lane: String,
    pub workflow: crate::Digest,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
}
#[cfg(any(test, feature = "fixture-only"))]
pub struct Rc1ApproverParts {
    pub principal: String,
    pub account: String,
    pub lane: String,
    pub key: String,
    pub signature_profile: String,
}
impl InspectedCanonicalPayload {
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn rc1_approver(&self) -> Option<Rc1ApproverParts> {
        let Payload::Rc1(value) = &self.payload else {
            return None;
        };
        Some(Rc1ApproverParts {
            principal: value.approver.principal.clone(),
            account: value.approver.account.clone(),
            lane: value.approver.lane.clone(),
            key: value.approver.key.clone(),
            signature_profile: value.approver.signature_profile.clone(),
        })
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn threshold_metadata(&self) -> Option<ThresholdMetadataParts> {
        let Payload::Metadata(value) = &self.payload else {
            return None;
        };
        Some(ThresholdMetadataParts {
            candidate: value.root.body.candidate_sha256.0,
            inventory: value.root.body.inventory_sha256.0,
            versions: std::collections::BTreeMap::from([
                ("root".into(), value.root.body.version),
                ("targets".into(), value.targets.body.version),
                ("snapshot".into(), value.snapshot.body.version),
                ("timestamp".into(), value.timestamp.body.version),
            ]),
            rollback_floor: value.root.body.rollback_floor,
            expires_at: value
                .root
                .body
                .expires_at
                .min(value.targets.body.expires_at)
                .min(value.snapshot.body.expires_at)
                .min(value.timestamp.body.expires_at),
            revocation_epoch: value.root.body.revocation_epoch,
            frozen: value.root.body.frozen,
            root_keyset: value
                .root
                .body
                .keyset
                .iter()
                .map(|key| (key.key_id.clone(), key.public_key.0.as_bytes()))
                .collect(),
            targets_keyset: value
                .targets
                .body
                .keyset
                .iter()
                .map(|key| (key.key_id.clone(), key.public_key.0.as_bytes()))
                .collect(),
            snapshot_key_id: value.snapshot.body.key_id.clone(),
            timestamp_key_id: value.timestamp.body.key_id.clone(),
            channel_selector: value.targets.body.targets.first()?.channel_selector.clone(),
            root_predecessor_body: value.root.body.predecessor_body_sha256.0,
            root_predecessor_keyset: value.root.body.predecessor_keyset_sha256.0,
            root_body: super::rc2_threshold::canonical_body(&value.root.body).ok()?,
            targets_body: super::rc2_threshold::canonical_body(&value.targets.body).ok()?,
            snapshot_body: super::rc2_threshold::canonical_body(&value.snapshot.body).ok()?,
            timestamp_body: super::rc2_threshold::canonical_body(&value.timestamp.body).ok()?,
            root_successor: value
                .root
                .successor_authorization
                .iter()
                .map(|proof| (proof.key_id.clone(), proof.signature.0))
                .collect(),
            root_self: value
                .root
                .self_proof
                .iter()
                .map(|proof| (proof.key_id.clone(), proof.signature.0))
                .collect(),
            targets_root: value
                .targets
                .root_authorization
                .iter()
                .map(|proof| (proof.key_id.clone(), proof.signature.0))
                .collect(),
            targets_self: value
                .targets
                .self_proof
                .iter()
                .map(|proof| (proof.key_id.clone(), proof.signature.0))
                .collect(),
            snapshot_signature: (
                value.snapshot.signature.key_id.clone(),
                value.snapshot.signature.signature.0,
            ),
            timestamp_signature: (
                value.timestamp.signature.key_id.clone(),
                value.timestamp.signature.signature.0,
            ),
            targets: threshold::targets(value.targets.body.targets.clone())?,
        })
    }
    pub(crate) fn rc2_operational_identities(&self) -> Option<[[&str; 5]; 4]> {
        let Payload::Rc2Auth(value) = &self.payload else {
            return None;
        };
        Some([
            parts(&value.signer),
            parts(&value.runner),
            parts(&value.reviewer),
            parts(&value.update_issuer),
        ])
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn artifact_record(&self) -> Option<ArtifactRecordParts> {
        let Payload::Record(value) = &self.payload else {
            return None;
        };
        Some(ArtifactRecordParts {
            artifact_slot_id: value.artifact_slot_id.clone(),
            platform: value.platform.clone(),
            candidate: value.parent_candidate_sha256.0,
            artifact: value.artifact_sha256.0,
            artifact_length: value.artifact_length,
            authorization: value.signing_authorization_sha256.0,
            workflow: value.workflow_sha256.0,
            signer: owned_parts(&value.signer),
            runner: owned_parts(&value.runner),
            effect_namespace: value.effect_namespace.clone(),
            effect_generation: value.effect_generation,
            operation: value.operation.clone(),
            pre_sign_digest: value.pre_sign_artifact_sha256.0,
            pre_sign_length: value.pre_sign_artifact_length,
            attestations: [
                value.native_signature_attestation_sha256.0,
                value.certificate_chain_attestation_sha256.0,
                value.timestamp_attestation_sha256.0,
                value.secret_scan_attestation_sha256.0,
                value.advisory_scan_attestation_sha256.0,
                value.package_inspection_attestation_sha256.0,
                value.install_attestation_sha256.0,
                value.upgrade_attestation_sha256.0,
                value.rollback_attestation_sha256.0,
                value.uninstall_attestation_sha256.0,
            ],
        })
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn rc2_plan(&self) -> Option<Rc2PlanParts> {
        let Payload::Rc2Auth(value) = &self.payload else {
            return None;
        };
        let [linux_appimage, linux_deb, windows] = value.pre_sign_artifacts.as_slice() else {
            return None;
        };
        Some(Rc2PlanParts {
            candidate: value.parent_candidate_sha256.0,
            workflow: value.workflow_sha256.0,
            signer: owned_parts(&value.signer),
            runner: owned_parts(&value.runner),
            effect_namespace: value.effect_namespace.clone(),
            effect_generation: value.effect_generation,
            artifacts: [
                (
                    linux_appimage.artifact_slot_id.clone(),
                    linux_appimage.platform.clone(),
                    linux_appimage.expected_artifact_sha256.0,
                    linux_appimage.expected_artifact_length,
                ),
                (
                    linux_deb.artifact_slot_id.clone(),
                    linux_deb.platform.clone(),
                    linux_deb.expected_artifact_sha256.0,
                    linux_deb.expected_artifact_length,
                ),
                (
                    windows.artifact_slot_id.clone(),
                    windows.platform.clone(),
                    windows.expected_artifact_sha256.0,
                    windows.expected_artifact_length,
                ),
            ],
            valid_from: value.valid_from,
            expires_at: value.expires_at,
            revocation_epoch: value.revocation_epoch,
        })
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn publication(&self) -> Option<PublicationParts> {
        let Payload::Publication(value) = &self.payload else {
            return None;
        };
        Some(PublicationParts {
            candidate: value.candidate_sha256.0,
            inventory: value.inventory_sha256.0,
            metadata: value.metadata_set_sha256.0,
            report: value.report_sha256.0,
            channel: value.channel.clone(),
            destination: value.destination.clone(),
        })
    }
    pub(crate) fn rc3_authorization(&self) -> Option<Rc3AuthorizationParts> {
        let Payload::Rc3Auth(value) = &self.payload else {
            return None;
        };
        Some(Rc3AuthorizationParts {
            executor_principal: value.executor_principal.clone(),
            lane: value.lane.clone(),
        })
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn rc3_raw_bindings(&self) -> Option<Rc3RawBindings> {
        let Payload::Rc3Auth(value) = &self.payload else {
            return None;
        };
        Some(Rc3RawBindings {
            inventory: value.inventory_sha256.0,
            report: value.report_sha256.0,
            manifest: value.publication_manifest_sha256.0,
            channel: value.channel.clone(),
            destination: value.destination.clone(),
            idempotency_namespace: value.idempotency_namespace.clone(),
            executor: value.executor_principal.clone(),
            lane: value.lane.clone(),
            workflow: value.workflow_sha256.0,
            valid_from: value.valid_from,
            expires_at: value.expires_at,
            revocation_epoch: value.revocation_epoch,
        })
    }
}
