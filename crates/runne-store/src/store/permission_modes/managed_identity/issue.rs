use runne_domain::id::IntegrityDigest;

use super::lease;
use super::model::ClosedRulesManagedIdentityV2;

pub(in crate::store::permission_modes) fn bind_legacy_challenge(
    identity: ClosedRulesManagedIdentityV2,
    legacy_issued_digest: IntegrityDigest,
) -> ClosedRulesManagedIdentityV2 {
    lease::with_challenge(identity, *legacy_issued_digest.as_bytes())
}
