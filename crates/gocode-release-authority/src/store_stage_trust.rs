//! Authenticated fixture trust snapshot used by the co-located stage context.

use crate::{Digest, TransactionOutcome, store::CommandFingerprint};

#[derive(Clone)]
pub struct StoredStageTrust {
    pub(crate) now: u64,
    pub(crate) utc: String,
    pub(crate) root_epoch: u64,
    pub(crate) role_floor: u64,
}
impl Default for StoredStageTrust {
    fn default() -> Self {
        Self {
            now: 1,
            utc: "2026-08-13T00:00:03Z".into(),
            root_epoch: 1,
            role_floor: 1,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ThresholdAckDelivery {
    Pending {
        admission: Digest,
        revision: u64,
    },
    Delivering {
        admission: Digest,
        revision: u64,
        command: String,
    },
}
impl ThresholdAckDelivery {
    pub(crate) const fn claim(&self) -> (Digest, u64) {
        match self {
            Self::Pending {
                admission,
                revision,
            }
            | Self::Delivering {
                admission,
                revision,
                ..
            } => (*admission, *revision),
        }
    }
}

#[derive(Clone)]
pub struct ThresholdAckTombstone {
    pub(crate) admission: Digest,
    pub(crate) claim_revision: u64,
    pub(crate) command: String,
    pub(crate) fingerprint: CommandFingerprint,
    pub(crate) outcome: TransactionOutcome,
}
