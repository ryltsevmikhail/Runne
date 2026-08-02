//! Integration tests for daemon bootstrap (Phase 4, Task 5).
//!
//! Covers all six crash states plus concurrent and recovery scenarios.

include!("bootstrap_integration_split_parts/part_01.rs");
include!("bootstrap_integration_split_parts/part_02.rs");
