use serde::{Deserialize, Serialize};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::messages::BootstrapAck;
use super::{
    BootstrapControlReply, DesktopOffer, MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES,
    QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN, QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
    QualificationBootstrapControlError, RootIssuedProof, RootPrepared, RunBinding,
};

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum ReplyWire {
    #[serde(rename = "desktop_offer")]
    DesktopOffer {
        domain: String,
        version: u8,
        role: String,
        desktop_challenge: [u8; 32],
        offer_id: [u8; 32],
        workflow_run_id: String,
        source_revision: [u8; 20],
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        namespace_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
        profile_sha256: [u8; 32],
        expires_at: u64,
        run_not_after: u64,
    },
    #[serde(rename = "root_prepared")]
    RootPrepared {
        domain: String,
        version: u8,
        role: String,
        offer_id: [u8; 32],
        workflow_run_id: String,
        source_revision: [u8; 20],
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        namespace_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
        profile_sha256: [u8; 32],
        expires_at: u64,
        run_not_after: u64,
    },
    #[serde(rename = "bootstrap_ack")]
    BootstrapAck {
        domain: String,
        version: u8,
        role: String,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        workflow_run_id: String,
        source_revision: [u8; 20],
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        namespace_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
        profile_sha256: [u8; 32],
        proof_sha256: [u8; 32],
        run_not_after: u64,
    },
    #[serde(rename = "root_issued_proof")]
    RootIssuedProof {
        domain: String,
        version: u8,
        role: String,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        signed_proof: String,
    },
}

pub(super) fn encode(
    value: &BootstrapControlReply,
) -> Result<Vec<u8>, QualificationBootstrapControlError> {
    canonical(&ReplyWire::from(value))
}
pub(super) fn decode(
    bytes: &[u8],
) -> Result<BootstrapControlReply, QualificationBootstrapControlError> {
    let wire: ReplyWire = canonical_decode(bytes)?;
    match wire {
        ReplyWire::DesktopOffer {
            domain,
            version,
            role,
            desktop_challenge,
            offer_id,
            workflow_run_id,
            source_revision,
            candidate_sha256,
            raw_v3_tuple_sha256,
            namespace_sha256,
            manifest_sha256,
            profile_sha256,
            expires_at,
            run_not_after,
        } => {
            header(&domain, version, &role)?;
            let binding = RunBinding::new(
                &workflow_run_id,
                source_revision,
                candidate_sha256,
                raw_v3_tuple_sha256,
                namespace_sha256,
                manifest_sha256,
                profile_sha256,
            )?;
            Ok(BootstrapControlReply::DesktopOffer(DesktopOffer::new(
                desktop_challenge,
                offer_id,
                binding,
                expires_at,
                run_not_after,
            )?))
        }
        ReplyWire::RootPrepared {
            domain,
            version,
            role,
            offer_id,
            workflow_run_id,
            source_revision,
            candidate_sha256,
            raw_v3_tuple_sha256,
            namespace_sha256,
            manifest_sha256,
            profile_sha256,
            expires_at,
            run_not_after,
        } => {
            header(&domain, version, &role)?;
            let binding = RunBinding::new(
                &workflow_run_id,
                source_revision,
                candidate_sha256,
                raw_v3_tuple_sha256,
                namespace_sha256,
                manifest_sha256,
                profile_sha256,
            )?;
            Ok(BootstrapControlReply::RootPrepared(RootPrepared::new(
                offer_id,
                binding,
                expires_at,
                run_not_after,
            )?))
        }
        ReplyWire::BootstrapAck {
            domain,
            version,
            role,
            offer_id,
            daemon_challenge,
            workflow_run_id,
            source_revision,
            candidate_sha256,
            raw_v3_tuple_sha256,
            namespace_sha256,
            manifest_sha256,
            profile_sha256,
            proof_sha256,
            run_not_after,
        } => {
            header(&domain, version, &role)?;
            let binding = RunBinding::new(
                &workflow_run_id,
                source_revision,
                candidate_sha256,
                raw_v3_tuple_sha256,
                namespace_sha256,
                manifest_sha256,
                profile_sha256,
            )?;
            Ok(BootstrapControlReply::BootstrapAck(BootstrapAck::new(
                offer_id,
                daemon_challenge,
                binding,
                proof_sha256,
                run_not_after,
            )?))
        }
        ReplyWire::RootIssuedProof {
            domain,
            version,
            role,
            offer_id,
            daemon_challenge,
            signed_proof,
        } => {
            header(&domain, version, &role)?;
            let signed_proof = URL_SAFE_NO_PAD
                .decode(signed_proof)
                .map_err(|_| QualificationBootstrapControlError::InvalidMessage)?;
            Ok(BootstrapControlReply::RootIssuedProof(
                RootIssuedProof::new(offer_id, daemon_challenge, signed_proof)?,
            ))
        }
    }
}
impl From<&BootstrapControlReply> for ReplyWire {
    fn from(value: &BootstrapControlReply) -> Self {
        match value {
            BootstrapControlReply::DesktopOffer(value) => Self::DesktopOffer {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "reply".into(),
                desktop_challenge: value.desktop_challenge,
                offer_id: value.offer_id,
                workflow_run_id: value.binding.workflow_run_id.clone(),
                source_revision: value.binding.source_revision,
                candidate_sha256: value.binding.candidate_sha256,
                raw_v3_tuple_sha256: value.binding.raw_v3_tuple_sha256,
                namespace_sha256: value.binding.namespace_sha256,
                manifest_sha256: value.binding.manifest_sha256,
                profile_sha256: value.binding.profile_sha256,
                expires_at: value.expires_at,
                run_not_after: value.run_not_after,
            },
            BootstrapControlReply::RootPrepared(value) => Self::RootPrepared {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "reply".into(),
                offer_id: value.offer_id,
                workflow_run_id: value.binding.workflow_run_id.clone(),
                source_revision: value.binding.source_revision,
                candidate_sha256: value.binding.candidate_sha256,
                raw_v3_tuple_sha256: value.binding.raw_v3_tuple_sha256,
                namespace_sha256: value.binding.namespace_sha256,
                manifest_sha256: value.binding.manifest_sha256,
                profile_sha256: value.binding.profile_sha256,
                expires_at: value.expires_at,
                run_not_after: value.run_not_after,
            },
            BootstrapControlReply::BootstrapAck(value) => Self::BootstrapAck {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "reply".into(),
                offer_id: value.offer_id,
                daemon_challenge: value.daemon_challenge,
                workflow_run_id: value.binding.workflow_run_id.clone(),
                source_revision: value.binding.source_revision,
                candidate_sha256: value.binding.candidate_sha256,
                raw_v3_tuple_sha256: value.binding.raw_v3_tuple_sha256,
                namespace_sha256: value.binding.namespace_sha256,
                manifest_sha256: value.binding.manifest_sha256,
                profile_sha256: value.binding.profile_sha256,
                proof_sha256: value.proof_sha256,
                run_not_after: value.run_not_after,
            },
            BootstrapControlReply::RootIssuedProof(value) => Self::RootIssuedProof {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "reply".into(),
                offer_id: value.offer_id(),
                daemon_challenge: value.daemon_challenge(),
                signed_proof: URL_SAFE_NO_PAD.encode(value.signed_proof()),
            },
        }
    }
}
fn header(domain: &str, version: u8, role: &str) -> Result<(), QualificationBootstrapControlError> {
    (domain == QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN
        && version == QUALIFICATION_BOOTSTRAP_CONTROL_VERSION
        && role == "reply")
        .then_some(())
        .ok_or(QualificationBootstrapControlError::InvalidMessage)
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, QualificationBootstrapControlError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| QualificationBootstrapControlError::InvalidMessage)?;
    (bytes.len() <= MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES)
        .then_some(bytes)
        .ok_or(QualificationBootstrapControlError::InvalidMessage)
}
fn canonical_decode<T: for<'a> Deserialize<'a> + Serialize>(
    bytes: &[u8],
) -> Result<T, QualificationBootstrapControlError> {
    if bytes.is_empty() || bytes.len() > MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES {
        return Err(QualificationBootstrapControlError::InvalidMessage);
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| QualificationBootstrapControlError::InvalidMessage)?;
    (canonical(&value)?.as_slice() == bytes)
        .then_some(value)
        .ok_or(QualificationBootstrapControlError::InvalidMessage)
}
