//! Immutable reports and manifests used by production migration stages.

use std::collections::BTreeSet;

use runne_domain::timestamp::Timestamp;

use super::{
    error::MigrationError,
    ports::CutoverIntent,
    rollout::{CutoverPolicy, LegacyReferenceInventory},
    types::{
        ArtifactDigest, CohortSelector, FeatureProfileRef, MigrationCycleId, MigrationPlanId,
        RoutingGeneration, RoutingUnit, RuntimeGenerationRef,
    },
};

const MAX_ARTIFACT_REF_BYTES: usize = 256;
const MAX_TRANSITION_ID_BYTES: usize = 128;

include!("manifests_parts/base.rs");
include!("manifests_parts/report.rs");
include!("manifests_parts/cutover_types.rs");
include!("manifests_parts/cutover_impl.rs");
include!("manifests_parts/rollback_retirement.rs");
include!("manifests_parts/helpers.rs");
