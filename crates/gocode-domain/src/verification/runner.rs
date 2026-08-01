//! L0-L3 runner implementations with real execution paths.
use crate::verification::digest::{DigestContract, VerificationDigest};
use crate::verification::evaluation::*;
use crate::verification::evidence::{EvidenceItem, EvidenceLayer, EvidenceType, SensitivityLabel};
use crate::verification::identity::*;

include!("runner/types.rs");
include!("runner/l0.rs");
include!("runner/l1.rs");
include!("runner/l2s.rs");
include!("runner/l2i.rs");
include!("runner/l3.rs");
include!("runner/l4.rs");
include!("runner/gate.rs");

#[cfg(test)]
mod tests {
    include!("runner/tests.rs");
}
