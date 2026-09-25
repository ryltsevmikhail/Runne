const LINUX_PAIR_SECRET_RELAY_OFFER_DOMAIN: &[u8] = b"gocode/linux-pair-secret-relay-offer/v1\0";

/// Authenticator for one ancillary-FD offer after a validated lifecycle relay.
/// Its key is distinct from writer evidence and generic broker transfers.
#[derive(Clone)]
pub struct LinuxPairSecretRelayOfferAuthenticator {
    key: Zeroizing<[u8; 32]>,
}

impl LinuxPairSecretRelayOfferAuthenticator {
    /// Derives the relay-only key from the exact protected V3 activation.
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            key: Zeroizing::new(derive_key(
                keys.readiness_key(),
                LINUX_PAIR_SECRET_RELAY_OFFER_DOMAIN,
            )),
        }
    }

    /// Authenticates one fd offer against the exact lifecycle frame and writer channel.
    #[must_use]
    pub fn authenticate_offer(
        &self,
        lifecycle_frame: &[u8],
        channel_binding: &[u8; 32],
        publication_key: &[u8; 32],
        descriptor_count: u8,
    ) -> [u8; 32] {
        authenticated_mac(
            &self.key,
            LINUX_PAIR_SECRET_RELAY_OFFER_DOMAIN,
            &Self::record(
                lifecycle_frame,
                channel_binding,
                publication_key,
                descriptor_count,
            ),
        )
    }

    /// Verifies the offer in constant time using the same exact binding.
    #[must_use]
    pub fn verifies_offer(
        &self,
        lifecycle_frame: &[u8],
        channel_binding: &[u8; 32],
        publication_key: &[u8; 32],
        descriptor_count: u8,
        proof: &[u8; 32],
    ) -> bool {
        bool::from(
            self.authenticate_offer(
                lifecycle_frame,
                channel_binding,
                publication_key,
                descriptor_count,
            )
            .ct_eq(proof),
        )
    }

    fn record(
        lifecycle_frame: &[u8],
        channel_binding: &[u8; 32],
        publication_key: &[u8; 32],
        descriptor_count: u8,
    ) -> Vec<u8> {
        let frame_digest: [u8; 32] = Sha256::digest(lifecycle_frame).into();
        let mut record = Vec::with_capacity(97);
        record.extend_from_slice(&frame_digest);
        record.extend_from_slice(channel_binding);
        record.extend_from_slice(publication_key);
        record.push(descriptor_count);
        record
    }
}

impl std::fmt::Debug for LinuxPairSecretRelayOfferAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LinuxPairSecretRelayOfferAuthenticator(<redacted>)")
    }
}
