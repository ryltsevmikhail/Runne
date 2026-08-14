#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Neutral, non-authorizing validation for delegated release-stage payloads.

mod rc2;
mod rc3_v2;
mod rc3_v2_facts;
mod rc3_v2_graph;
mod rc3_v2_models;
mod stage_transition;
mod strict_json;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Closed payload kinds which may be carried by delegated stage envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalPayloadKind {
    /// RC1 qualification decision.
    Rc1Decision,
    /// RC2 signing authorization.
    Rc2Authorization,
    /// RC3 publication authorization.
    Rc3Authorization,
}

pub use rc3_v2::{
    PayloadKind as Rc3V2PayloadKind, ValidatedPayload as ValidatedRc3V2Payload,
    validate as validate_rc3_v2_payload,
};
pub use rc3_v2_facts::{Facts as Rc3V2Facts, IdentityFacts as Rc3V2IdentityFacts};
pub use rc3_v2_graph::validate as validate_rc3_v2_graph;
pub use stage_transition::StageTransitionReservation;

/// Neutral payload validation failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    /// The input is not strict canonical JSON for the selected payload schema.
    #[error("invalid canonical stage payload")]
    InvalidCanonicalPayload,
    /// Individually valid RC3 v2 leaves do not form one immutable binding graph.
    #[error("incoherent RC3 v2 graph")]
    IncoherentRc3V2Graph,
}

/// Typed, canonical payload verified structurally; this is not an authority credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCanonicalStagePayload {
    kind: CanonicalPayloadKind,
    canonical: Vec<u8>,
    sha256: [u8; 32],
}
impl ValidatedCanonicalStagePayload {
    /// Return the closed selected payload kind.
    #[must_use]
    pub const fn kind(&self) -> CanonicalPayloadKind {
        self.kind
    }
    /// Return the exact payload SHA-256.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    /// Return exact canonical payload bytes without the envelope line feed.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.canonical
    }
}

/// Validate exact canonical bytes for the allowed stage role schema.
///
/// # Errors
/// Returns an error when schema id is unrecognized, JSON is not canonical, or required
/// cross-field invariants for the selected payload fail.
pub fn validate_stage_payload(
    schema_id: &str,
    canonical: &[u8],
) -> Result<ValidatedCanonicalStagePayload, ContractError> {
    let kind = match schema_id {
        "gocode.release.rc1-qualification-decision/1" => CanonicalPayloadKind::Rc1Decision,
        "gocode.release.rc2-signing-authorization/1" => CanonicalPayloadKind::Rc2Authorization,
        // Legacy RC3 `/1` maps only for the legacy audit chain; every authority
        // admission path must reject it with `AuthorityVersionSuperseded` before use.
        "gocode.release.rc3-publication-authorization/1" => CanonicalPayloadKind::Rc3Authorization,
        _ => return Err(ContractError::InvalidCanonicalPayload),
    };
    let value =
        strict_json::parse(canonical).map_err(|()| ContractError::InvalidCanonicalPayload)?;
    let canonical_value = sorted(value.clone());
    let valid = match kind {
        CanonicalPayloadKind::Rc1Decision => {
            serde_json::from_value::<Rc1>(value).map(|x| valid_rc1(&x))
        }
        CanonicalPayloadKind::Rc2Authorization => {
            serde_json::from_value::<rc2::Rc2>(value).map(|x| rc2::valid(&x))
        }
        CanonicalPayloadKind::Rc3Authorization => {
            serde_json::from_value::<Rc3>(value).map(|x| valid_rc3(&x))
        }
    }
    .map_err(|_| ContractError::InvalidCanonicalPayload)?;
    if !valid {
        return Err(ContractError::InvalidCanonicalPayload);
    }
    let expected =
        serde_json::to_vec(&canonical_value).map_err(|_| ContractError::InvalidCanonicalPayload)?;
    if expected != canonical {
        return Err(ContractError::InvalidCanonicalPayload);
    }
    Ok(ValidatedCanonicalStagePayload {
        kind,
        canonical: canonical.to_vec(),
        sha256: Sha256::digest(canonical).into(),
    })
}

fn sorted(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sorted).collect())
        }
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(name, value)| (name, sorted(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        value => value,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rc1 {
    schema_version: String,
    candidate_binding_sha256: String,
    subject_sha256: String,
    matrix_sha256: String,
    bootstrap_sha256: String,
    candidate_sha256: String,
    policy_sha256: String,
    release_facts_sha256: String,
    approver: Identity,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
    disposition: String,
    signing_allowed: bool,
    publication_allowed: bool,
    external_effects: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    #[serde(rename = "principal_id")]
    principal: String,
    #[serde(rename = "account_id")]
    account: String,
    #[serde(rename = "lane_id")]
    lane: String,
    #[serde(rename = "key_id")]
    key: String,
    #[serde(rename = "signature_profile_id")]
    signature_profile: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rc3 {
    schema_version: String,
    inventory_sha256: String,
    report_sha256: String,
    publication_manifest_sha256: String,
    executor_principal: String,
    lane: String,
    workflow_sha256: String,
    idempotency_namespace: String,
    destination: String,
    channel: String,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
    no_effect: bool,
    external_effects: Vec<String>,
}
fn valid_rc1(x: &Rc1) -> bool {
    x.schema_version == "gocode.release.rc1-qualification-decision/1"
        && x.valid_from < x.expires_at
        && x.revocation_epoch > 0
        && x.disposition == "qualified_unsigned"
        && !x.signing_allowed
        && !x.publication_allowed
        && x.external_effects.is_empty()
        && ids(&[
            &x.approver.principal,
            &x.approver.account,
            &x.approver.lane,
            &x.approver.key,
            &x.approver.signature_profile,
        ])
        && digests(&[
            &x.candidate_binding_sha256,
            &x.subject_sha256,
            &x.matrix_sha256,
            &x.bootstrap_sha256,
            &x.candidate_sha256,
            &x.policy_sha256,
            &x.release_facts_sha256,
        ])
}
fn valid_rc3(x: &Rc3) -> bool {
    x.schema_version == "gocode.release.rc3-publication-authorization/1"
        && x.valid_from < x.expires_at
        && x.revocation_epoch > 0
        && x.no_effect
        && x.external_effects.is_empty()
        && matches!(x.channel.as_str(), "stable" | "beta" | "internal")
        && ids(&[&x.executor_principal, &x.lane, &x.idempotency_namespace])
        && destination(&x.destination)
        && digests(&[
            &x.inventory_sha256,
            &x.report_sha256,
            &x.publication_manifest_sha256,
            &x.workflow_sha256,
        ])
}

fn destination(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}
fn ids(values: &[&str]) -> bool {
    values.iter().all(|x| canonical_id(x))
}

/// Return whether an identifier satisfies the pinned canonical stage grammar.
#[must_use]
pub fn canonical_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}
pub(crate) fn digests(values: &[&str]) -> bool {
    values.iter().all(|x| {
        x.len() == 64
            && x.bytes()
                .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
    })
}
