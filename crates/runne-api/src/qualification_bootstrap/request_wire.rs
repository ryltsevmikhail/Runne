use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use super::messages::{RootConsumeRequest, RuntimeBootstrapRequest};
use super::{
    BootstrapControlRequest, DesktopOfferRequest, MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES,
    QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN, QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
    QualificationBootstrapControlError, RootPrepareRequest,
};

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum RequestWire {
    #[serde(rename = "desktop_offer_request")]
    DesktopOfferRequest {
        domain: String,
        version: u8,
        role: String,
        desktop_challenge: [u8; 32],
    },
    #[serde(rename = "root_prepare")]
    RootPrepare {
        domain: String,
        version: u8,
        role: String,
    },
    #[serde(rename = "runtime_bootstrap_request")]
    RuntimeBootstrap {
        domain: String,
        version: u8,
        role: String,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        profile_sha256: [u8; 32],
    },
    #[serde(rename = "root_arm")]
    RootArm {
        domain: String,
        version: u8,
        role: String,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        profile_sha256: [u8; 32],
    },
    #[serde(rename = "root_consume_request")]
    RootConsume {
        domain: String,
        version: u8,
        role: String,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        signed_proof: String,
    },
}

pub(super) fn encode(
    value: &BootstrapControlRequest,
) -> Result<Vec<u8>, QualificationBootstrapControlError> {
    canonical(&RequestWire::from(value))
}
pub(super) fn decode(
    bytes: &[u8],
) -> Result<BootstrapControlRequest, QualificationBootstrapControlError> {
    let wire: RequestWire = canonical_decode(bytes)?;
    match wire {
        RequestWire::DesktopOfferRequest {
            domain,
            version,
            role,
            desktop_challenge,
        } => {
            header(&domain, version, &role)?;
            Ok(BootstrapControlRequest::DesktopOffer(
                DesktopOfferRequest::new(desktop_challenge)?,
            ))
        }
        RequestWire::RootPrepare {
            domain,
            version,
            role,
        } => {
            header(&domain, version, &role)?;
            Ok(BootstrapControlRequest::RootPrepare(
                RootPrepareRequest::new(),
            ))
        }
        RequestWire::RuntimeBootstrap {
            domain,
            version,
            role,
            offer_id,
            daemon_challenge,
            candidate_sha256,
            raw_v3_tuple_sha256,
            profile_sha256,
        } => {
            header(&domain, version, &role)?;
            Ok(BootstrapControlRequest::RuntimeBootstrap(
                RuntimeBootstrapRequest::new(
                    offer_id,
                    daemon_challenge,
                    candidate_sha256,
                    raw_v3_tuple_sha256,
                    profile_sha256,
                )?,
            ))
        }
        RequestWire::RootArm {
            domain,
            version,
            role,
            offer_id,
            daemon_challenge,
            candidate_sha256,
            raw_v3_tuple_sha256,
            profile_sha256,
        } => {
            header(&domain, version, &role)?;
            Ok(BootstrapControlRequest::RootArm(
                RuntimeBootstrapRequest::new(
                    offer_id,
                    daemon_challenge,
                    candidate_sha256,
                    raw_v3_tuple_sha256,
                    profile_sha256,
                )?,
            ))
        }
        RequestWire::RootConsume {
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
            Ok(BootstrapControlRequest::RootConsume(
                RootConsumeRequest::new(offer_id, daemon_challenge, signed_proof)?,
            ))
        }
    }
}
impl From<&BootstrapControlRequest> for RequestWire {
    fn from(value: &BootstrapControlRequest) -> Self {
        match value {
            BootstrapControlRequest::DesktopOffer(value) => Self::DesktopOfferRequest {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "request".into(),
                desktop_challenge: value.desktop_challenge,
            },
            BootstrapControlRequest::RootPrepare(_) => Self::RootPrepare {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "request".into(),
            },
            BootstrapControlRequest::RuntimeBootstrap(value) => Self::RuntimeBootstrap {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "request".into(),
                offer_id: value.offer_id,
                daemon_challenge: value.daemon_challenge,
                candidate_sha256: value.candidate_sha256,
                raw_v3_tuple_sha256: value.raw_v3_tuple_sha256,
                profile_sha256: value.profile_sha256,
            },
            BootstrapControlRequest::RootArm(value) => Self::RootArm {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "request".into(),
                offer_id: value.offer_id,
                daemon_challenge: value.daemon_challenge,
                candidate_sha256: value.candidate_sha256,
                raw_v3_tuple_sha256: value.raw_v3_tuple_sha256,
                profile_sha256: value.profile_sha256,
            },
            BootstrapControlRequest::RootConsume(value) => Self::RootConsume {
                domain: QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN.into(),
                version: QUALIFICATION_BOOTSTRAP_CONTROL_VERSION,
                role: "request".into(),
                offer_id: value.offer_id,
                daemon_challenge: value.daemon_challenge,
                signed_proof: URL_SAFE_NO_PAD.encode(&value.signed_proof),
            },
        }
    }
}
fn header(domain: &str, version: u8, role: &str) -> Result<(), QualificationBootstrapControlError> {
    (domain == QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN
        && version == QUALIFICATION_BOOTSTRAP_CONTROL_VERSION
        && role == "request")
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
