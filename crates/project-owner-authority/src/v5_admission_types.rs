//! Authenticated state, typed CAS requests, and exact durable recovery results.

/// Exact root authority identity authenticated by durable storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootAuthorityIdentity5D {
    pub principal_id: String,
    pub controlling_account_id: String,
    pub lane_id: String,
    pub key_id: String,
    pub signature_profile_id: String,
    pub public_key: [u8; 32],
    pub key_epoch: u64,
}

/// Independent revocation floor for one exact delegated `(role, scope)`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RoleScopeFloor {
    pub role: String,
    pub scope: String,
    pub revocation_epoch: u64,
}

/// One authenticated durable state snapshot used as the expected CAS value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityStateSnapshot {
    pub durable_generation: u64,
    pub active_trust_generation: u64,
    pub active_receipt_generation: u64,
    pub active_allowlist_generation: u64,
    pub root: RootAuthorityIdentity5D,
    pub root_revocation_floor: u64,
    pub role_scope_floors: Vec<RoleScopeFloor>,
}

/// Typed promotion lineage identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionIdentity {
    pub receipt_sha256: [u8; 32],
    pub trust_config_sha256: String,
}
/// Typed immutable revision identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionIdentity {
    pub trust_generation: u64,
    pub receipt_generation: u64,
    pub allowlist_generation: u64,
    pub payload_schema_id: String,
    pub payload_schema_sha256: [u8; 32],
}
/// Typed command identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandIdentity {
    pub nonce: String,
    pub envelope_sha256: [u8; 32],
    pub payload_sha256: [u8; 32],
}
/// Exact durable reservation identity derived from the immutable request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationIdentity(pub [u8; 32]);
/// Exact durable outcome identity derived from the immutable request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeIdentity(pub [u8; 32]);

/// Exact persisted state returned for a new admission or identical recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedAdmission {
    pub reservation: ReservationIdentity,
    pub outcome: OutcomeIdentity,
}

/// Durable atomic admission result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableAdmission {
    /// This exact immutable request won the expected CAS and was persisted.
    NewlyAdmitted {
        /// Exact reservation and outcome persisted atomically.
        persisted: PersistedAdmission,
        /// Authenticated state after the successful CAS transition.
        state: AuthorityStateSnapshot,
    },
    /// This exact immutable request was already persisted and may recover after expiry.
    ExistingSame {
        /// Exact reservation and outcome read from durable storage.
        persisted: PersistedAdmission,
        /// Authenticated current state; recovery performs no transition.
        state: AuthorityStateSnapshot,
    },
}
impl DurableAdmission {
    pub(crate) const fn persisted(&self) -> &PersistedAdmission {
        match self {
            Self::NewlyAdmitted { persisted, .. } | Self::ExistingSame { persisted, .. } => {
                persisted
            }
        }
    }
}

/// Typed receipt `/5` CAS request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptV5AdmissionRequest {
    pub expected: AuthorityStateSnapshot,
    pub newly_admitted_state: AuthorityStateSnapshot,
    pub scope: crate::ReceiptV5AdmissionScope,
    pub validity: crate::ReceiptV5Validity,
    pub promotion: PromotionIdentity,
    pub revision: RevisionIdentity,
    pub command: CommandIdentity,
    pub reservation: ReservationIdentity,
    pub outcome: OutcomeIdentity,
}
/// Recovery-only receipt `/5` lookup; it cannot request a state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptV5RecoveryRequest {
    pub expected: AuthorityStateSnapshot,
    pub scope: crate::ReceiptV5AdmissionScope,
    pub validity: crate::ReceiptV5Validity,
    pub promotion: PromotionIdentity,
    pub revision: RevisionIdentity,
    pub command: CommandIdentity,
    pub reservation: ReservationIdentity,
    pub outcome: OutcomeIdentity,
}
/// Typed result of a new receipt `/5` CAS transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewlyAdmittedReceiptV5 {
    pub persisted: PersistedAdmission,
    pub state: AuthorityStateSnapshot,
}
/// Typed result of a recovery-only receipt `/5` lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingSameReceiptV5 {
    pub persisted: PersistedAdmission,
    pub state: AuthorityStateSnapshot,
}
/// Typed stage-envelope `/2` CAS request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageEnvelopeAdmissionRequest {
    pub expected: AuthorityStateSnapshot,
    pub newly_admitted_state: AuthorityStateSnapshot,
    pub scope: crate::V5AdmissionScope,
    pub promotion: PromotionIdentity,
    pub revision: RevisionIdentity,
    pub command: CommandIdentity,
    pub reservation: ReservationIdentity,
    pub outcome: OutcomeIdentity,
}
/// Typed evidence-envelope `/2` CAS request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceEnvelopeAdmissionRequest {
    pub expected: AuthorityStateSnapshot,
    pub newly_admitted_state: AuthorityStateSnapshot,
    pub scope: crate::V5AdmissionScope,
    pub promotion: PromotionIdentity,
    pub revision: RevisionIdentity,
    pub command: CommandIdentity,
    pub reservation: ReservationIdentity,
    pub outcome: OutcomeIdentity,
}
/// Typed destination-allowlist `/1` CAS request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationAllowlistAdmissionRequest {
    pub expected: AuthorityStateSnapshot,
    pub newly_admitted_state: AuthorityStateSnapshot,
    pub scope: crate::DestinationAllowlistAdmissionScope,
    pub promotion: PromotionIdentity,
    pub revision: RevisionIdentity,
    pub command: CommandIdentity,
    pub reservation: ReservationIdentity,
    pub outcome: OutcomeIdentity,
}

macro_rules! immutable_equality {
    ($type:ty, $($field:ident),+ $(,)?) => {
        impl $type {
            /// Compare the full immutable admission intent while excluding the
            /// per-attempt pre/post CAS snapshots.
            #[must_use]
            pub fn same_admission_as(&self, other: &Self) -> bool {
                $(self.$field == other.$field)&&+
            }
        }
    };
}

immutable_equality!(
    ReceiptV5AdmissionRequest,
    scope,
    validity,
    promotion,
    revision,
    command,
    reservation,
    outcome,
);

impl ReceiptV5RecoveryRequest {
    /// Compare the full recovery intent with the originally persisted new
    /// admission while excluding only its per-attempt CAS snapshots.
    #[must_use]
    pub fn same_admission_as(&self, stored: &ReceiptV5AdmissionRequest) -> bool {
        self.scope == stored.scope
            && self.validity == stored.validity
            && self.promotion == stored.promotion
            && self.revision == stored.revision
            && self.command == stored.command
            && self.reservation == stored.reservation
            && self.outcome == stored.outcome
    }
}
immutable_equality!(
    StageEnvelopeAdmissionRequest,
    scope,
    promotion,
    revision,
    command,
    reservation,
    outcome,
);
immutable_equality!(
    EvidenceEnvelopeAdmissionRequest,
    scope,
    promotion,
    revision,
    command,
    reservation,
    outcome,
);
immutable_equality!(
    DestinationAllowlistAdmissionRequest,
    scope,
    promotion,
    revision,
    command,
    reservation,
    outcome,
);
