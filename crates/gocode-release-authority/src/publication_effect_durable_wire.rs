//! Serde wire shared by the canonical ledger codec and JSON Schema goldens.
#![allow(dead_code)]

use crate::publication_effect_intent::PublicationEffectIntentWire;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerWire {
    pub schema_version: String,
    pub claims: Vec<ClaimWire>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimWire {
    pub namespace: String,
    pub intent: PublicationEffectIntentWire,
    pub state: String,
    pub reconciliations: u8,
    pub settlement_sha256: Option<String>,
    pub commands: Vec<CommandRecordWire>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRecordWire {
    pub command: CommandWire,
    pub command_fingerprint_sha256: String,
    pub outcome: OutcomeWire,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandWire {
    Claim {
        command_id: String,
        intent: PublicationEffectIntentWire,
        observed_at: u64,
        current_revocation_epoch: u64,
        current_allowlist_generation: u64,
    },
    Dispatch {
        command_id: String,
        intent: PublicationEffectIntentWire,
        capability_sha256: String,
        observed_at: u64,
        current_revocation_epoch: u64,
        current_allowlist_generation: u64,
    },
    MarkUncertain {
        command_id: String,
        intent: PublicationEffectIntentWire,
        capability_sha256: String,
    },
    SucceedSettlement {
        command_id: String,
        intent: PublicationEffectIntentWire,
        capability_sha256: String,
        evidence_sha256: String,
    },
    ReconcileSucceeded {
        command_id: String,
        intent: PublicationEffectIntentWire,
        capability_sha256: String,
        evidence_sha256: String,
    },
    ReconcileAbsent {
        command_id: String,
        intent: PublicationEffectIntentWire,
        capability_sha256: String,
        evidence_sha256: String,
    },
    ReconcileInconclusive {
        command_id: String,
        intent: PublicationEffectIntentWire,
        capability_sha256: String,
        evidence_sha256: String,
    },
    Reclaim {
        command_id: String,
        intent: PublicationEffectIntentWire,
        capability_sha256: String,
        observed_at: u64,
        current_revocation_epoch: u64,
        current_allowlist_generation: u64,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeWire {
    pub state: String,
    pub generation: u64,
    pub evidence_sha256: Option<String>,
}
