/// Durable result of the one-shot pre-effect compare-and-swap.
///
/// ```compile_fail
/// use runne_store::provider::ProviderEffectStartReceipt;
///
/// fn duplicate(receipt: ProviderEffectStartReceipt) {
///     let _ = receipt.clone();
/// }
/// ```
#[derive(PartialEq, Eq)]
pub struct ProviderEffectStartReceipt {
    expires_at: i64,
    attempt_id: [u8; 16],
    permit_id: [u8; 16],
    provider_idempotency_key: String,
    prepared_digest: [u8; 32],
    render_digest: [u8; 32],
    profile_digest: [u8; 32],
    fencing_token: u64,
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
    deadline: Instant,
    credential_provider: String,
    credential_version: u64,
    credential_ref_digest: [u8; 32],
    credential_owner: [u8; 16],
    credential_expires_at: i64,
    credential_fencing_token: u64,
}

impl std::fmt::Debug for ProviderEffectStartReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderEffectStartReceipt")
            .field("expires_at", &self.expires_at)
            .field("binding", &"<redacted>")
            .field("deadline", &"<monotonic>")
            .finish()
    }
}

impl ProviderEffectStartReceipt {
    /// Absolute Unix-second effect expiry loaded after the committed CAS.
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the single monotonic deadline captured after durable readback.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Measures the complete durable effect-start authority for one-use
    /// credential materialization. The derived monotonic deadline is omitted;
    /// its authoritative absolute expiry is included instead.
    #[must_use]
    pub fn credential_read_receipt_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(CREDENTIAL_READ_RECEIPT_DOMAIN);
        hash.update(self.expires_at.to_be_bytes());
        hash.update(self.attempt_id);
        hash.update(self.permit_id);
        hash.update(
            u64::try_from(self.provider_idempotency_key.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(self.provider_idempotency_key.as_bytes());
        hash.update(self.prepared_digest);
        hash.update(self.render_digest);
        hash.update(self.profile_digest);
        hash.update(self.fencing_token.to_be_bytes());
        hash.update(self.token_reservation_id);
        hash.update(self.cost_reservation_id);
        hash.update(
            u64::try_from(self.credential_provider.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(self.credential_provider.as_bytes());
        hash.update(self.credential_version.to_be_bytes());
        hash.update(self.credential_ref_digest);
        hash.update(self.credential_owner);
        hash.update(self.credential_expires_at.to_be_bytes());
        hash.update(self.credential_fencing_token.to_be_bytes());
        hash.finalize().into()
    }

    /// Returns whether this receipt is bound to the exact admitted claim.
    pub fn matches_claim(&self, claim: &ProviderDispatchClaim) -> bool {
        self.attempt_id == *claim.attempt_id.as_bytes()
            && self.permit_id == claim.permit_id
            && self.provider_idempotency_key == claim.provider_idempotency_key
            && self.prepared_digest == claim.prepared_digest
            && self.render_digest == claim.render_digest
            && self.profile_digest == claim.profile_digest
            && self.fencing_token == claim.fencing_token
            && self.token_reservation_id == claim.token_reservation_id
            && self.cost_reservation_id == claim.cost_reservation_id
    }

    /// Returns whether this receipt names the exact credential authority
    /// committed atomically with the effect-start intent.
    pub fn matches_credential(&self, binding: &CredentialDispatchBinding) -> bool {
        self.credential_provider == binding.version_ref().provider().as_str()
            && self.credential_version == binding.version_ref().version()
            && self.credential_ref_digest == *binding.version_ref().ref_digest()
            && self.credential_owner == *binding.owner()
            && self.credential_expires_at == binding.expires_at()
            && self.credential_fencing_token == binding.fencing_token()
    }
}
use sha2::{Digest as _, Sha256};

const CREDENTIAL_READ_RECEIPT_DOMAIN: &[u8] =
    b"gocode/provider-effect-start/credential-read-receipt/v1\0";
