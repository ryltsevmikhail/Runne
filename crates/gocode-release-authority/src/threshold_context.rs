//! Atomic threshold admission; callers never supply durable state or recovery decisions.
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

use crate::threshold_scope::{ThresholdAckProof, ThresholdAckRequest, ThresholdAdmissionScope};
use crate::threshold_signatures::{verify_one, verify_role};
use crate::{AuthorityError, Digest};
/// Strict metadata facts extracted only while prevalidating the exact payload DAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdMetadataEvidence {
    pub(crate) root_keyset: Vec<(String, [u8; 32])>,
    pub(crate) targets_keyset: Vec<(String, [u8; 32])>,
    pub(crate) snapshot_key: String,
    pub(crate) timestamp_key: String,
    pub(crate) channel_selector: String,
    pub(crate) root_predecessor_body: Digest,
    pub(crate) root_predecessor_keyset: Digest,
    pub(crate) root_body: Vec<u8>,
    pub(crate) targets_body: Vec<u8>,
    pub(crate) snapshot_body: Vec<u8>,
    pub(crate) timestamp_body: Vec<u8>,
    pub(crate) root_successor: Vec<(String, [u8; 64])>,
    pub(crate) root_self: Vec<(String, [u8; 64])>,
    pub(crate) targets_root: Vec<(String, [u8; 64])>,
    pub(crate) targets_self: Vec<(String, [u8; 64])>,
    pub(crate) snapshot_signature: (String, [u8; 64]),
    pub(crate) timestamp_signature: (String, [u8; 64]),
    pub(crate) expires_at: u64,
    pub(crate) revocation_epoch: u64,
    pub(crate) frozen: bool,
    pub(crate) next_versions: BTreeMap<String, u64>,
    pub(crate) rollback_floor: u64,
}
/// Store- and bundle-bound request presented exactly once to one backend transaction.
pub struct ThresholdAdmissionRequest<'a> {
    pub(crate) receipt: &'a crate::SigningAuthorizedReceipt,
    pub(crate) bundle: &'a crate::FixturePrevalidatedSignedBundle,
    pub(crate) evidence: &'a ThresholdMetadataEvidence,
}
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedThresholdTransition {
    scope: ThresholdAdmissionScope,
    expected_generation: u64,
    next: ThresholdVerificationState,
    admission_id: Digest,
}
/// One durable outcome; `ExistingSame` is allowed only for an exact immutable journal match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThresholdAdmission {
    NewlyAdmitted { admission_id: Digest },
    ExistingSame { admission_id: Digest },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdVerificationState {
    pub versions: BTreeMap<String, u64>,
    pub rollback_floor: u64,
    pub revocation_floor: u64,
    pub frozen: bool,
    pub generation: u64,
    pub root_keys: BTreeMap<String, [u8; 32]>,
    pub targets_keys: BTreeMap<String, [u8; 32]>,
    pub snapshot_key: (String, [u8; 32]),
    pub timestamp_key: (String, [u8; 32]),
    pub channel_policy_id: Option<String>,
    pub role_bodies: BTreeMap<String, Vec<u8>>,
    pub role_digests: BTreeMap<String, Digest>,
}
impl ThresholdMetadataEvidence {
    pub(crate) fn verifies_against(&self, state: &ThresholdVerificationState) -> bool {
        unique_registered_keys(state)
            && self.snapshot_key == state.snapshot_key.0
            && self.timestamp_key == state.timestamp_key.0
            && state.channel_policy_id.as_deref() == Some(self.channel_selector.as_str())
            && crate::threshold_context_predecessor::matches(self, state)
            && verify_role(
                "root-successor",
                &self.root_body,
                &self.root_successor,
                &state.root_keys,
            )
            && verify_role(
                "root-self",
                &self.root_body,
                &self.root_self,
                &crate::threshold_context_predecessor::keyset(&self.root_keyset),
            )
            && verify_role(
                "targets-root",
                &self.targets_body,
                &self.targets_root,
                &crate::threshold_context_predecessor::keyset(&self.root_keyset),
            )
            && verify_role(
                "targets-self",
                &self.targets_body,
                &self.targets_self,
                &crate::threshold_context_predecessor::keyset(&self.targets_keyset),
            )
            && verify_one(
                "snapshot",
                &self.snapshot_body,
                &self.snapshot_signature,
                &state.snapshot_key,
            )
            && verify_one(
                "timestamp",
                &self.timestamp_body,
                &self.timestamp_signature,
                &state.timestamp_key,
            )
            && unique_successor_keys(self, state)
    }
}
impl ThresholdAdmissionRequest<'_> {
    #[must_use]
    pub fn scope(&self) -> ThresholdAdmissionScope {
        ThresholdAdmissionScope {
            authority_instance: self.receipt.authority_instance(),
            promotion: self.receipt.promotion().0.clone(),
            revision: self.receipt.revision(),
            command: self.receipt.command().into(),
            authorization: self.receipt.authorization(),
            commitment: self.bundle.commitment(),
            candidate: self.bundle.candidate(),
            inventory: self.bundle.inventory(),
            metadata: self.bundle.metadata(),
            report: self.bundle.report(),
        }
    }
    #[must_use]
    pub const fn receipt(&self) -> &crate::SigningAuthorizedReceipt {
        self.receipt
    }
    #[must_use]
    pub const fn bundle(&self) -> &crate::FixturePrevalidatedSignedBundle {
        self.bundle
    }
    /// Authenticate and seal the exact successor which an external backend may persist.
    ///
    /// # Errors
    /// Returns an error unless all trusted state, time, signature, version, and rollback facts
    /// match the immutable request.
    pub fn validate_new(
        &self,
        state: &ThresholdVerificationState,
        now: u64,
    ) -> Result<AuthenticatedThresholdTransition, AuthorityError> {
        let evidence = self.evidence;
        let valid_epoch = evidence.revocation_epoch == state.revocation_floor;
        let valid = !state.frozen
            && !evidence.frozen
            && valid_epoch
            && now < evidence.expires_at
            && evidence.rollback_floor >= state.rollback_floor
            && evidence.next_versions.iter().all(|(role, next)| {
                state
                    .versions
                    .get(role)
                    .and_then(|current| current.checked_add(1))
                    .is_some_and(|next_version| next == &next_version)
            })
            && evidence.next_versions.len() == state.versions.len()
            && evidence.verifies_against(state);
        if !valid {
            return Err(AuthorityError::BindingMismatch);
        }
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(AuthorityError::BindingMismatch)?;
        let mut next = state.clone();
        next.versions = evidence.next_versions.clone();
        next.rollback_floor = evidence.rollback_floor;
        next.generation = generation;
        next.root_keys = crate::threshold_context_predecessor::keyset(&evidence.root_keyset);
        next.targets_keys = crate::threshold_context_predecessor::keyset(&evidence.targets_keyset);
        next.role_bodies = BTreeMap::from([
            ("root".into(), evidence.root_body.clone()),
            ("targets".into(), evidence.targets_body.clone()),
            ("snapshot".into(), evidence.snapshot_body.clone()),
            ("timestamp".into(), evidence.timestamp_body.clone()),
        ]);
        next.role_digests = next
            .role_bodies
            .iter()
            .map(|(role, body)| {
                (
                    role.clone(),
                    Digest::from_bytes(Sha256::digest(body).into()),
                )
            })
            .collect();
        let scope = self.scope();
        Ok(AuthenticatedThresholdTransition {
            admission_id: admission_id(&scope, state.generation, &next),
            scope,
            expected_generation: state.generation,
            next,
        })
    }
}
impl AuthenticatedThresholdTransition {
    /// Return the exact immutable scope admitted by this sealed transition.
    #[must_use]
    pub const fn scope(&self) -> &ThresholdAdmissionScope {
        &self.scope
    }
    /// Return the generation that must still be current at persistence time.
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    /// Return the exact authenticated successor state.
    #[must_use]
    pub const fn next_state(&self) -> &ThresholdVerificationState {
        &self.next
    }
    /// Return the stable journal identity for this exact sealed transition.
    #[must_use]
    pub const fn admission_id(&self) -> Digest {
        self.admission_id
    }
}
fn admission_id(
    scope: &ThresholdAdmissionScope,
    generation: u64,
    next: &ThresholdVerificationState,
) -> Digest {
    let mut transcript = b"gocode.release.threshold-admission/1\0".to_vec();
    append(&mut transcript, &scope.digest().as_bytes());
    append(&mut transcript, &generation.to_be_bytes());
    append(&mut transcript, &next.generation.to_be_bytes());
    append(&mut transcript, &next.rollback_floor.to_be_bytes());
    for (role, version) in &next.versions {
        append(&mut transcript, role.as_bytes());
        append(&mut transcript, &version.to_be_bytes());
    }
    Digest::from_bytes(Sha256::digest(transcript).into())
}
fn append(transcript: &mut Vec<u8>, field: &[u8]) {
    transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
    transcript.extend_from_slice(field);
}

fn unique_registered_keys(state: &ThresholdVerificationState) -> bool {
    let mut keys = std::collections::BTreeSet::new();
    state
        .root_keys
        .values()
        .chain(state.targets_keys.values())
        .chain([&state.snapshot_key.1, &state.timestamp_key.1])
        .all(|key| keys.insert(*key))
}

fn unique_successor_keys(
    evidence: &ThresholdMetadataEvidence,
    state: &ThresholdVerificationState,
) -> bool {
    let mut keys = std::collections::BTreeSet::new();
    evidence
        .root_keyset
        .iter()
        .chain(&evidence.targets_keyset)
        .map(|(_, key)| key)
        .chain([&state.snapshot_key.1, &state.timestamp_key.1])
        .all(|key| keys.insert(*key))
}

/// A durable threshold backend owns time, freeze, revocation, registered keys, CAS and journal.
pub trait ThresholdVerificationContext {
    /// Return an exact immutable journal match before a new admission is evaluated.
    ///
    /// # Errors
    /// Returns an error when trusted state, signatures, reservation, or journal diverges.
    fn recover_existing(
        &self,
        request: &ThresholdAdmissionRequest<'_>,
    ) -> Result<Option<ThresholdAdmission>, AuthorityError>;
    /// Return the trusted state and clock captured by the backend transaction.
    ///
    /// # Errors
    /// Returns an error when the trusted durable state cannot be loaded.
    fn trusted_state_and_now(&self) -> Result<(ThresholdVerificationState, u64), AuthorityError>;
    /// Atomically persist precisely the supplied sealed transition, or recover an exact journal.
    ///
    /// # Errors
    /// Returns an error when the generation, journal, or durable write diverges.
    fn persist_new(
        &self,
        transition: AuthenticatedThresholdTransition,
    ) -> Result<ThresholdAdmission, AuthorityError>;
    /// Acknowledge an exact claim or recover its exact durable acknowledgement tombstone.
    ///
    /// # Errors
    /// Returns an error for divergent claims or unavailable durable acknowledgement state.
    fn acknowledge_or_recover(
        &self,
        request: &ThresholdAckRequest<'_>,
    ) -> Result<ThresholdAckProof, AuthorityError>;
}
