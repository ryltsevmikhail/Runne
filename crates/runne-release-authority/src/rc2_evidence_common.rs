//! Shared fixture-only raw cryptographic evidence primitives.
#![allow(clippy::redundant_pub_crate)] // Sibling fixture modules share these crate-private types.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

use crate::{AuthorityError, Digest};

#[derive(Debug, Eq, PartialEq)]
pub struct RawRc2Evidence {
    pub(crate) raw: Vec<u8>,
    pub(crate) signature: [u8; 64],
}
impl RawRc2Evidence {
    #[must_use]
    pub const fn from_detached(raw: Vec<u8>, signature: [u8; 64]) -> Self {
        Self { raw, signature }
    }
    #[must_use]
    pub fn signed(raw: Vec<u8>, key: &SigningKey) -> Self {
        let signature = key.sign(&raw).to_bytes();
        Self { raw, signature }
    }
}

#[allow(clippy::struct_field_names)] // JSON contract names are externally fixed.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceIdentity {
    pub(crate) principal_id: String,
    pub(crate) account_id: String,
    pub(crate) lane_id: String,
    pub(crate) key_id: String,
    pub(crate) signature_profile_id: String,
}
impl EvidenceIdentity {
    pub(crate) fn valid(&self) -> bool {
        [
            &self.principal_id,
            &self.account_id,
            &self.lane_id,
            &self.key_id,
            &self.signature_profile_id,
        ]
        .into_iter()
        .all(|id| valid_identifier(id))
    }
    pub(crate) fn matches_parts(&self, parts: &[String; 5]) -> bool {
        self.principal_id == parts[0]
            && self.account_id == parts[1]
            && self.lane_id == parts[2]
            && self.key_id == parts[3]
            && self.signature_profile_id == parts[4]
    }
    pub(crate) fn matches_refs(&self, parts: &[&str; 5]) -> bool {
        self.principal_id == parts[0]
            && self.account_id == parts[1]
            && self.lane_id == parts[2]
            && self.key_id == parts[3]
            && self.signature_profile_id == parts[4]
    }
}

pub(crate) fn valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|x| x.is_ascii_alphanumeric() || matches!(x, b'.' | b'_' | b'-'))
}

/// One registered fixture verification key pinned to its full operational identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureEvidenceKeyRegistration {
    pub(crate) identity: EvidenceIdentity,
    pub(crate) public_key: [u8; 32],
}
impl FixtureEvidenceKeyRegistration {
    #[must_use]
    pub fn new(
        principal_id: &str,
        account_id: &str,
        lane_id: &str,
        key_id: &str,
        signature_profile_id: &str,
        public_key: [u8; 32],
    ) -> Self {
        Self {
            identity: EvidenceIdentity {
                principal_id: principal_id.into(),
                account_id: account_id.into(),
                lane_id: lane_id.into(),
                key_id: key_id.into(),
                signature_profile_id: signature_profile_id.into(),
            },
            public_key,
        }
    }
}

/// Fixture trust snapshot captured by the verifier, never supplied as callback verdicts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureEvidenceTrustState {
    now: u64,
    revocation_epoch: u64,
    generation: u64,
    registrations: Vec<FixtureEvidenceKeyRegistration>,
}
/// Immutable trusted facts retained by every verified RC2 evidence handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceTrustBinding {
    pub(crate) now: u64,
    pub(crate) revocation_epoch: u64,
    pub(crate) generation: u64,
    pub(crate) registrations_digest: Digest,
}
impl FixtureEvidenceTrustState {
    /// Construct a closed fixture trust state. No identity, key ID, or public key may alias.
    ///
    /// # Errors
    /// Returns an error for a zero epoch/generation or ambiguous registered authority.
    pub fn try_new(
        now: u64,
        revocation_epoch: u64,
        generation: u64,
        registrations: Vec<FixtureEvidenceKeyRegistration>,
    ) -> Result<Self, AuthorityError> {
        let mut identities = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        if revocation_epoch == 0
            || generation == 0
            || registrations.iter().any(|registration| {
                !registration.identity.valid()
                    || !identities.insert(registration.identity.clone())
                    || !key_ids.insert(registration.identity.key_id.clone())
                    || !public_keys.insert(registration.public_key)
            })
        {
            return Err(AuthorityError::BindingMismatch);
        }
        Ok(Self {
            now,
            revocation_epoch,
            generation,
            registrations,
        })
    }
    pub(crate) fn binding(&self) -> EvidenceTrustBinding {
        EvidenceTrustBinding {
            now: self.now,
            revocation_epoch: self.revocation_epoch,
            generation: self.generation,
            registrations_digest: registration_set_digest(&self.registrations),
        }
    }
    pub(crate) const fn timing(&self) -> (u64, u64) {
        (self.now, self.revocation_epoch)
    }
    #[must_use]
    pub fn registrations(&self) -> &[FixtureEvidenceKeyRegistration] {
        &self.registrations
    }
}

fn registration_set_digest(registrations: &[FixtureEvidenceKeyRegistration]) -> Digest {
    let mut registrations = registrations.to_vec();
    registrations.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut bytes = b"gocode.release.rc2-evidence-registration-set/1\0".to_vec();
    for registration in registrations {
        for identifier in [
            registration.identity.principal_id,
            registration.identity.account_id,
            registration.identity.lane_id,
            registration.identity.key_id,
            registration.identity.signature_profile_id,
        ] {
            bytes.extend_from_slice(&(identifier.len() as u64).to_be_bytes());
            bytes.extend_from_slice(identifier.as_bytes());
        }
        bytes.extend_from_slice(&registration.public_key);
    }
    Digest::from_bytes(Sha256::digest(bytes).into())
}

#[allow(clippy::needless_pass_by_value)] // Raw evidence is consumed at the trust boundary.
pub(crate) fn verify<T: DeserializeOwned + Serialize>(
    evidence: RawRc2Evidence,
    trust: &FixtureEvidenceTrustState,
    identity: &EvidenceIdentity,
    valid_from: u64,
    expires_at: u64,
    revocation_epoch: u64,
) -> Result<(T, Digest), AuthorityError> {
    if valid_from >= expires_at
        || trust.now < valid_from
        || trust.now >= expires_at
        || revocation_epoch != trust.revocation_epoch
        || !identity.valid()
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let value = crate::wire::strict_json::parse(&evidence.raw)?;
    let parsed: T =
        serde_json::from_value(value).map_err(|_| AuthorityError::NonCanonicalPayload)?;
    let mut canonical = serde_json::to_vec(&crate::wire::sorted_value(
        serde_json::to_value(&parsed).map_err(|_| AuthorityError::NonCanonicalPayload)?,
    ))
    .map_err(|_| AuthorityError::NonCanonicalPayload)?;
    canonical.push(b'\n');
    if canonical != evidence.raw {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    let registration = trust
        .registrations
        .iter()
        .find(|item| item.identity == *identity)
        .ok_or(AuthorityError::BindingMismatch)?;
    let key = VerifyingKey::from_bytes(&registration.public_key)
        .map_err(|_| AuthorityError::BindingMismatch)?;
    key.verify(&evidence.raw, &Signature::from_bytes(&evidence.signature))
        .map_err(|_| AuthorityError::BindingMismatch)?;
    Ok((
        parsed,
        Digest::from_bytes(Sha256::digest(&evidence.raw[..evidence.raw.len() - 1]).into()),
    ))
}
