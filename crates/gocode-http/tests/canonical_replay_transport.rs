//! Behavioral contract for authenticated replay transport over real SQLite.

#[path = "support/canonical_replay_transport.rs"]
mod canonical_replay_transport_support;

use canonical_replay_transport_support::*;
include!("canonical_replay_transport_split_parts/part_01.rs");
include!("canonical_replay_transport_split_parts/part_02.rs");
include!("canonical_replay_transport_split_parts/part_03.rs");
include!("canonical_replay_transport_split_parts/part_04.rs");
include!("canonical_replay_transport_split_parts/part_05.rs");
