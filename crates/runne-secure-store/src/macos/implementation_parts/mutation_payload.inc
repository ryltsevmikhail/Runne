use ring::rand::SecureRandom as _;

/// Versioned wrapper that binds the ECIES-wrapped per-payload key to the
/// profile-bound payload envelope produced by [`crate::payload_crypto`].
const MUTATION_PAYLOAD_MAGIC: &[u8; 8] = b"GMPE1\0\0\0";
const MUTATION_PAYLOAD_HEADER_BYTES: usize = 10;
const PAYLOAD_KEY_BYTES: usize = 32;
const MAX_WRAPPED_PAYLOAD_KEY_BYTES: usize = 512;
const PAYLOAD_CRYPTO_MIN_BYTES: usize = 12 + 16;

impl crate::security_anchor::SecurityProfileLockBackend for NativeSecurityLock {
    fn seal(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        let seal = self
            .lock
            .seal(self.profile, database, generation, transaction, previous)
            .map_err(|_| SecureStoreError::Unavailable)?;
        SealedTransactionTag::from_storage(seal.as_bytes().to_vec())
    }

    fn verify(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
        seal: &[u8],
    ) -> Result<(), SecureStoreError> {
        self.lock
            .verify(
                self.profile,
                database,
                generation,
                transaction,
                previous,
                seal,
            )
            .map_err(|_| SecureStoreError::InvalidSeal)
    }

    fn encrypt_mutation_payload(
        &self,
        database: [u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SecureStoreError> {
        let mut payload_key = Zeroizing::new([0_u8; PAYLOAD_KEY_BYTES]);
        ring::rand::SystemRandom::new()
            .fill(payload_key.as_mut())
            .map_err(|_| SecureStoreError::Unavailable)?;
        let wrapped = self
            .lock
            .encrypt_payload_key(self.profile, payload_key.as_ref())
            .map_err(|_| SecureStoreError::Unavailable)?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_PAYLOAD_KEY_BYTES {
            return Err(SecureStoreError::Unavailable);
        }
        let body = crate::payload_crypto::encrypt(
            payload_key.as_ref(),
            self.profile,
            database,
            aad,
            plaintext,
        )?;
        compose_envelope(&wrapped, &body)
    }

    fn decrypt_mutation_payload(
        &self,
        database: [u8; 32],
        aad: &[u8],
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        let (wrapped, body) = split_envelope(envelope)?;
        let payload_key = self
            .lock
            .decrypt_payload_key(self.profile, wrapped)
            .map_err(|_| SecureStoreError::InvalidSeal)?;
        crate::payload_crypto::decrypt(payload_key.as_ref(), self.profile, database, aad, body)
    }

    fn supports_mutation_payload_encryption(&self) -> bool {
        true
    }
}

fn compose_envelope(wrapped: &[u8], body: &[u8]) -> Result<Vec<u8>, SecureStoreError> {
    let wrapped_len = u16::try_from(wrapped.len()).map_err(|_| SecureStoreError::Unavailable)?;
    let mut envelope =
        Vec::with_capacity(MUTATION_PAYLOAD_HEADER_BYTES + wrapped.len() + body.len());
    envelope.extend_from_slice(MUTATION_PAYLOAD_MAGIC);
    envelope.extend_from_slice(&wrapped_len.to_be_bytes());
    envelope.extend_from_slice(wrapped);
    envelope.extend_from_slice(body);
    Ok(envelope)
}

fn split_envelope(envelope: &[u8]) -> Result<(&[u8], &[u8]), SecureStoreError> {
    if envelope.len() < MUTATION_PAYLOAD_HEADER_BYTES + PAYLOAD_CRYPTO_MIN_BYTES
        || !envelope.starts_with(MUTATION_PAYLOAD_MAGIC)
    {
        return Err(SecureStoreError::InvalidSeal);
    }
    let wrapped_len = usize::from(u16::from_be_bytes([envelope[8], envelope[9]]));
    if wrapped_len == 0 || wrapped_len > MAX_WRAPPED_PAYLOAD_KEY_BYTES {
        return Err(SecureStoreError::InvalidSeal);
    }
    let body_start = MUTATION_PAYLOAD_HEADER_BYTES + wrapped_len;
    if envelope.len() < body_start + PAYLOAD_CRYPTO_MIN_BYTES {
        return Err(SecureStoreError::InvalidSeal);
    }
    Ok((
        &envelope[MUTATION_PAYLOAD_HEADER_BYTES..body_start],
        &envelope[body_start..],
    ))
}

#[cfg(test)]
mod mutation_payload_tests {
    use super::{MUTATION_PAYLOAD_MAGIC, compose_envelope, split_envelope};

    fn wrapped() -> Vec<u8> {
        vec![0xA5; 97]
    }

    fn body() -> Vec<u8> {
        let mut body = vec![0x5A; 12];
        body.extend_from_slice(&[0x3C; 32]);
        body
    }

    #[test]
    fn envelope_round_trips_wrapped_key_and_body() {
        let envelope = compose_envelope(&wrapped(), &body()).unwrap();
        assert!(envelope.starts_with(MUTATION_PAYLOAD_MAGIC));
        let (parsed_wrapped, parsed_body) = split_envelope(&envelope).unwrap();
        assert_eq!(parsed_wrapped, wrapped());
        assert_eq!(parsed_body, body());
    }

    #[test]
    fn envelope_without_magic_is_rejected() {
        let mut envelope = compose_envelope(&wrapped(), &body()).unwrap();
        envelope[0] ^= 0xFF;
        assert!(split_envelope(&envelope).is_err());
    }

    #[test]
    fn envelope_with_truncated_header_or_body_is_rejected() {
        let envelope = compose_envelope(&wrapped(), &body()).unwrap();
        for length in 0..envelope.len() {
            if length >= 10 + 2 + 28 {
                continue;
            }
            assert!(split_envelope(&envelope[..length]).is_err());
        }
    }

    #[test]
    fn envelope_with_zero_or_oversized_wrapped_key_is_rejected() {
        let mut zero = compose_envelope(&wrapped(), &body()).unwrap();
        zero[8] = 0;
        zero[9] = 0;
        assert!(split_envelope(&zero).is_err());

        let mut oversized = compose_envelope(&wrapped(), &body()).unwrap();
        oversized[8] = 0x02;
        oversized[9] = 0x01;
        assert!(split_envelope(&oversized).is_err());
    }

    #[test]
    fn envelope_with_body_shorter_than_payload_crypto_is_rejected() {
        let short_body = vec![0x5A; 27];
        let envelope = compose_envelope(&wrapped(), &short_body).unwrap();
        assert!(split_envelope(&envelope).is_err());
    }
}
