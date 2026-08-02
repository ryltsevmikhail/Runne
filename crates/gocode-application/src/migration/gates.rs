//! Durable migration evidence contracts.

use gocode_domain::timestamp::Timestamp;
use sha2::{Digest, Sha256};

use super::{
    state::MigrationPhase,
    types::{ArtifactDigest, CohortSelector, GateFamily, GateId, RuntimeGenerationRef},
};

include!("gates/evidence.rs");
include!("gates/migration.rs");
include!("gates/policy.rs");
include!("gates/validated.rs");

#[cfg(test)]
mod tests {
    include!("gates/tests.rs");
}
