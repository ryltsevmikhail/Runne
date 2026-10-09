use runne_api::{PermissionControlContextV1, PermissionControlModeChallengeV1};
use sha2::Digest as _;

#[expect(
    clippy::redundant_pub_crate,
    reason = "The private module is re-exported only at the crate boundary."
)]
pub(crate) fn native_confirmation_binding_digest(
    context: &PermissionControlContextV1,
    challenge: &PermissionControlModeChallengeV1,
) -> Result<[u8; 32], ()> {
    let expires_at = i64::try_from(challenge.ceremony_expires_at_unix_ms).map_err(|_| ())?;
    if context.public_request_digest == [0; 32]
        || challenge.issued_challenge_binding_digest == [0; 32]
        || challenge.challenge_id == [0; 16]
        || context.issued_at_unix_ms >= challenge.ceremony_expires_at_unix_ms
        || challenge.ceremony_expires_at_unix_ms > context.expires_at_unix_ms
    {
        return Err(());
    }
    let mut hash = sha2::Sha256::new();
    hash.update(b"runne:d21:permission-mode:native-confirmation-binding:v2\0");
    hash.update(context.public_request_digest);
    hash.update(challenge.managed_policy_revision.to_be_bytes());
    hash.update(challenge.managed_policy_digest);
    hash.update(challenge.issued_challenge_binding_digest);
    hash.update(context.protected_session_id);
    hash.update(expires_at.to_be_bytes());
    hash.update(challenge.native_warning_version.to_be_bytes());
    Ok(hash.finalize().into())
}
