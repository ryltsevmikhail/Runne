//! Wire-level identifiers — independent of domain crates.
//!
//! All UUIDv7 newtypes, bounded strings, version/revision types,
//! and identifier-size constants.

use core::fmt;
use std::str::FromStr;

// ── Supporting types ───────────────────────────────────────────────────────

include!("id/uuid.rs");
include!("id/nonce.rs");
include!("id/versions.rs");

#[cfg(test)]
mod tests {
    include!("id/tests.rs");
}
