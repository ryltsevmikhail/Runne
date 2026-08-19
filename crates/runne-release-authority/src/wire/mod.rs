//! Strict, typed, raw-bound release payload parsing.
#![allow(clippy::redundant_pub_crate)] // Fixture evidence reuses duplicate-safe canonical parsing.

mod common;
mod rc1;
mod rc1_facts;
mod rc2;
mod rc2_threshold;
mod rc3;
pub mod semantics;
mod snapshot;
mod snapshot_parts;
pub(crate) mod strict_json;

use sha2::{Digest as _, Sha256};

use crate::AuthorityError;
#[cfg(any(test, feature = "fixture-only"))]
pub use rc1_facts::ReleaseFacts;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CanonicalPayloadKind {
    Rc1Decision,
    UnsignedManifest,
    Rc2Authorization,
    ArtifactRecord,
    ThresholdMetadata,
    Inventory,
    VerificationReport,
    PublicationManifest,
    Rc3Authorization,
    Snapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Payload {
    Rc1(rc1::Rc1Decision),
    Manifest(rc1::UnsignedManifest),
    Rc2Auth(Box<rc2::SigningAuthorization>),
    Record(Box<rc2::ArtifactRecord>),
    Metadata(Box<rc2::ThresholdMetadata>),
    Inventory(rc2::Inventory),
    Report(rc2::VerificationReport),
    Publication(rc3::PublicationManifest),
    Rc3Auth(rc3::PublicationAuthorization),
    Snapshot(snapshot::Snapshot),
}

#[cfg(any(test, feature = "fixture-only"))]
pub struct RawDag {
    pub records: Vec<crate::Digest>,
    pub inventory: crate::Digest,
    pub metadata: crate::Digest,
    pub report: crate::Digest,
    pub manifest: crate::Digest,
    pub binding: crate::Digest,
    pub unsigned_manifest: crate::Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Canonical, typed bytes inspected before an outer stage-envelope verification.
///
/// This value is not a production authority credential and cannot admit promotion state.
pub struct InspectedCanonicalPayload {
    kind: CanonicalPayloadKind,
    raw: Vec<u8>,
    sha256: [u8; 32],
    payload: Payload,
}
impl InspectedCanonicalPayload {
    /// Inspects only duplicate-safe, compact, sorted UTF-8 JSON with exactly one LF.
    ///
    /// It performs no signature, delegation, freshness, revocation, or authority-store check.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, duplicate, noncanonical, or semantically invalid input.
    pub fn parse(kind: CanonicalPayloadKind, raw: &[u8]) -> Result<Self, AuthorityError> {
        if raw.is_empty() || !raw.ends_with(b"\n") {
            return Err(AuthorityError::NonCanonicalPayload);
        }
        std::str::from_utf8(raw).map_err(|_| AuthorityError::NonCanonicalPayload)?;
        let value = strict_json::parse(raw)?;
        let payload = decode(kind, value)?;
        if canonical(&payload)? != raw {
            return Err(AuthorityError::NonCanonicalPayload);
        }
        Ok(Self {
            kind,
            raw: raw.to_vec(),
            sha256: Sha256::digest(&raw[..raw.len() - 1]).into(),
            payload,
        })
    }
    #[must_use]
    pub const fn kind(&self) -> CanonicalPayloadKind {
        self.kind
    }
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub(crate) const fn raw_digest(&self) -> crate::Digest {
        crate::Digest::from_bytes(self.sha256)
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) const fn release_facts_digest(&self) -> Option<crate::Digest> {
        match &self.payload {
            Payload::Rc1(value) => Some(value.release_facts_sha256.0),
            Payload::Manifest(_) => Some(self.raw_digest()),
            _ => None,
        }
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) const fn release_facts(&self) -> Option<&ReleaseFacts> {
        match &self.payload {
            Payload::Manifest(value) => Some(&value.release_facts),
            _ => None,
        }
    }
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn matches_binding(&self, binding: &crate::CandidateBinding) -> bool {
        match &self.payload {
            Payload::Rc1(value) => {
                value.subject_sha256.0 == binding.subject()
                    && value.matrix_sha256.0 == binding.matrix()
                    && value.bootstrap_sha256.0 == binding.bootstrap()
                    && value.candidate_sha256.0 == binding.candidate()
                    && value.policy_sha256.0 == binding.policy()
                    && binding
                        .release_facts()
                        .is_none_or(|facts| value.release_facts_sha256.0 == facts)
            }
            Payload::Manifest(value) => {
                value.subject_sha256.0 == binding.subject()
                    && value.matrix_sha256.0 == binding.matrix()
                    && value.bootstrap_sha256.0 == binding.bootstrap()
                    && value.candidate_sha256.0 == binding.candidate()
                    && value.policy_sha256.0 == binding.policy()
                    && binding
                        .release_facts()
                        .is_none_or(|facts| facts == self.raw_digest())
            }
            _ => self.candidate_digest() == Some(binding.candidate()),
        }
    }
    #[must_use]
    pub const fn candidate_digest(&self) -> Option<crate::Digest> {
        match &self.payload {
            Payload::Rc1(x) => Some(x.candidate_sha256.0),
            Payload::Manifest(x) => Some(x.candidate_sha256.0),
            Payload::Rc2Auth(x) => Some(x.parent_candidate_sha256.0),
            Payload::Record(x) => Some(x.parent_candidate_sha256.0),
            Payload::Metadata(x) => Some(x.root.body.candidate_sha256.0),
            Payload::Inventory(x) => Some(x.parent_candidate_sha256.0),
            Payload::Publication(x) => Some(x.candidate_sha256.0),
            Payload::Snapshot(x) => Some(x.candidate_sha256.0),
            Payload::Report(_) | Payload::Rc3Auth(_) => None,
        }
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn artifact_platform(&self) -> Option<&str> {
        match &self.payload {
            Payload::Record(x) => Some(&x.platform),
            _ => None,
        }
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn binds_raw_dag(&self, dag: &RawDag) -> bool {
        match &self.payload {
            Payload::Rc1(x) => x.candidate_binding_sha256.0 == dag.binding,
            Payload::Rc2Auth(x) => x.unsigned_manifest_sha256.0 == dag.unsigned_manifest,
            Payload::Inventory(x) => x
                .artifact_records
                .iter()
                .map(|value| value.0)
                .eq(dag.records.iter().copied()),
            Payload::Metadata(x) => x.root.body.inventory_sha256.0 == dag.inventory,
            Payload::Report(x) => {
                x.inventory_sha256.0 == dag.inventory && x.metadata_set_sha256.0 == dag.metadata
            }
            Payload::Publication(x) => {
                x.inventory_sha256.0 == dag.inventory
                    && x.metadata_set_sha256.0 == dag.metadata
                    && x.report_sha256.0 == dag.report
            }
            Payload::Rc3Auth(x) => {
                x.inventory_sha256.0 == dag.inventory
                    && x.report_sha256.0 == dag.report
                    && x.publication_manifest_sha256.0 == dag.manifest
            }
            Payload::Snapshot(x) => x.candidate_binding_sha256.0 == dag.binding,
            Payload::Manifest(_) | Payload::Record(_) => true,
        }
    }
}

fn decode(kind: CanonicalPayloadKind, value: serde_json::Value) -> Result<Payload, AuthorityError> {
    macro_rules! typed {
        ($model:ty, $variant:ident, $check:path) => {{
            let x: $model =
                serde_json::from_value(value).map_err(|_| AuthorityError::NonCanonicalPayload)?;
            $check(&x)?;
            Ok(Payload::$variant(x))
        }};
    }
    match kind {
        CanonicalPayloadKind::Rc1Decision => typed!(rc1::Rc1Decision, Rc1, rc1::validate_decision),
        CanonicalPayloadKind::UnsignedManifest => {
            typed!(rc1::UnsignedManifest, Manifest, rc1::validate_manifest)
        }
        CanonicalPayloadKind::Rc2Authorization => {
            let value =
                serde_json::from_value(value).map_err(|_| AuthorityError::NonCanonicalPayload)?;
            rc2::auth(&value)?;
            Ok(Payload::Rc2Auth(Box::new(value)))
        }
        CanonicalPayloadKind::ArtifactRecord => {
            if value
                .get("schema_version")
                .and_then(serde_json::Value::as_str)
                == Some(rc2::RECORD_V1)
            {
                return Err(AuthorityError::AuthorityVersionSuperseded);
            }
            let x: rc2::ArtifactRecord =
                serde_json::from_value(value).map_err(|_| AuthorityError::NonCanonicalPayload)?;
            rc2::record(&x)?;
            Ok(Payload::Record(Box::new(x)))
        }
        CanonicalPayloadKind::ThresholdMetadata => {
            let x: rc2::ThresholdMetadata =
                serde_json::from_value(value).map_err(|_| AuthorityError::NonCanonicalPayload)?;
            rc2::metadata(&x)?;
            Ok(Payload::Metadata(Box::new(x)))
        }
        CanonicalPayloadKind::Inventory => typed!(rc2::Inventory, Inventory, rc2::inventory),
        CanonicalPayloadKind::VerificationReport => {
            typed!(rc2::VerificationReport, Report, rc2::report)
        }
        CanonicalPayloadKind::PublicationManifest => {
            superseded(&value, rc3::MANIFEST)?;
            typed!(rc3::PublicationManifest, Publication, rc3::manifest)
        }
        CanonicalPayloadKind::Rc3Authorization => {
            superseded(&value, rc3::AUTH)?;
            typed!(rc3::PublicationAuthorization, Rc3Auth, rc3::auth)
        }
        CanonicalPayloadKind::Snapshot => typed!(snapshot::Snapshot, Snapshot, snapshot::validate),
    }
}
fn superseded(value: &serde_json::Value, legacy: &str) -> Result<(), AuthorityError> {
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        == Some(legacy)
    {
        return Err(AuthorityError::AuthorityVersionSuperseded);
    }
    Ok(())
}
fn canonical(payload: &Payload) -> Result<Vec<u8>, AuthorityError> {
    let value = match payload {
        Payload::Rc1(x) => serde_json::to_value(x),
        Payload::Manifest(x) => serde_json::to_value(x),
        Payload::Rc2Auth(x) => serde_json::to_value(x),
        Payload::Record(x) => serde_json::to_value(x),
        Payload::Metadata(x) => serde_json::to_value(x),
        Payload::Inventory(x) => serde_json::to_value(x),
        Payload::Report(x) => serde_json::to_value(x),
        Payload::Publication(x) => serde_json::to_value(x),
        Payload::Rc3Auth(x) => serde_json::to_value(x),
        Payload::Snapshot(x) => serde_json::to_value(x),
    }
    .map_err(|_| AuthorityError::NonCanonicalPayload)?;
    let mut raw = serde_json::to_vec(&sorted_value(value))
        .map_err(|_| AuthorityError::NonCanonicalPayload)?;
    raw.push(b'\n');
    Ok(raw)
}
pub fn sorted_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sorted_value).collect())
        }
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, sorted_value(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        x => x,
    }
}
