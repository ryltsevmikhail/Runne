//! SQLite schema migration and connection integrity checks.

include!("schema/open.rs");
include!("schema/database.rs");
include!("schema/checks.rs");
include!("schema/tests.rs");
