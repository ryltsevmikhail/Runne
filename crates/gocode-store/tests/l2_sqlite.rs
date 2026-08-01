//! L2-I: SQLite integration tests for gocode-store.
//!
//! Uses a real temporary SQLite file and `StoreTransaction` for full
//! persistence tests. Tests the complete lifecycle through the service
//! layer, dedup, conflicts, reopen, concurrent writes, clock regression,
//! and fail-closed behavior on schema corruption.

include!("l2_sqlite_split_parts/part_01.rs");
include!("l2_sqlite_split_parts/part_02.rs");
include!("l2_sqlite_split_parts/part_03.rs");
include!("l2_sqlite_split_parts/part_04.rs");
include!("l2_sqlite_split_parts/part_05.rs");
include!("l2_sqlite_split_parts/part_06.rs");
include!("l2_sqlite_split_parts/part_07.rs");
