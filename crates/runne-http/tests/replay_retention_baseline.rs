//! Authenticated HTTP retention-gap baseline proof over a V17 SQLite store.

#[path = "replay_retention_baseline_parts/support.rs"]
mod support;

use support::*;

include!("replay_retention_baseline_parts/retention_gap.rs");
include!("replay_retention_baseline_parts/conversation_marker.rs");
include!("replay_retention_baseline_parts/resume_cleanup.rs");
include!("replay_retention_baseline_parts/resume_delivery_race.rs");
