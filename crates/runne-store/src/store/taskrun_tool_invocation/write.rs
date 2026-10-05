use super::validate::{
    approval_matches, effect_digest, encode_sources, ensure_no_unresolved,
    load_binding_for_validation, load_budget, same_assignment, validate_binding, validate_task,
    verify_sources,
};
use super::*;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::Digest;

include!("write/propose_approval.rs");
include!("write/claim_reconcile.rs");
include!("write/result_release.rs");
include!("write/area_proof.rs");
include!("write/budget.rs");
