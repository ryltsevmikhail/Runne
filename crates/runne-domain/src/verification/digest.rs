//! Canonical digest types and domain-separated digest contracts.
//! SHA-256 only for v1.

use sha2::{Digest as _, Sha256};
use std::fmt;

include!("digest/types.rs");
include!("digest/contract.rs");
include!("digest/errors.rs");

#[cfg(test)]
mod tests {
    include!("digest/tests.rs");
}
