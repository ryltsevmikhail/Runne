//! Fail-closed RC3 v2 structural leaf inspection.

use crate::AuthorityError;

/// Reject the only legacy RC3 stage kind before a fixture store reserves or mutates state.
#[cfg(any(test, feature = "fixture-only"))]
pub const fn reject_legacy_fixture_ingress(
    kind: gocode_promotion_contracts::CanonicalPayloadKind,
) -> Result<(), AuthorityError> {
    match kind {
        gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => {
            Err(AuthorityError::AuthorityVersionSuperseded)
        }
        _ => Ok(()),
    }
}

/// Inspect a closed RC3 v2 structural leaf before the owner-only admission boundary.
///
/// This function never creates authority, mutates durable state, or exposes executor capability.
///
/// # Errors
/// Returns `AuthorityVersionSuperseded` for active legacy payloads and `PolicyUnresolved` for
/// structurally valid v2 payloads until owner-verified handles and policies are available.
pub fn inspect_rc3_v2_leaf(schema_id: &str, raw: &[u8]) -> Result<(), AuthorityError> {
    if matches!(
        schema_id,
        "gocode.release.publication-manifest/1" | "gocode.release.rc3-publication-authorization/1"
    ) {
        return Err(AuthorityError::AuthorityVersionSuperseded);
    }
    let canonical = raw
        .strip_suffix(b"\n")
        .filter(|bytes| !bytes.ends_with(b"\n"))
        .ok_or(AuthorityError::BindingMismatch)?;
    gocode_promotion_contracts::validate_rc3_v2_payload(schema_id, canonical)
        .map_err(|_| AuthorityError::BindingMismatch)?;
    Err(AuthorityError::PolicyUnresolved)
}
