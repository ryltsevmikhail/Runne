use ring::{
    aead, hkdf,
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "payload_crypto_tests.rs"]
mod tests;

const KEY_DOMAIN: &[u8] = b"runne/v7-mutation-payload/aead-key/v1\0";
const NONCE_LEN: usize = 12;

struct AeadKey([u8; 32]);
impl hkdf::KeyType for AeadKey {
    fn len(&self) -> usize {
        self.0.len()
    }
}

pub fn encrypt(
    anchor_key: &[u8],
    profile: [u8; 32],
    database: [u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, crate::SecureStoreError> {
    let key = derive(anchor_key, profile, database)?;
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key.as_ref())
        .map_err(|_| crate::SecureStoreError::Unavailable)?;
    let key = aead::LessSafeKey::new(unbound);
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| crate::SecureStoreError::Unavailable)?;
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| crate::SecureStoreError::Unavailable)?;
    let mut ciphertext = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut *ciphertext)
        .map_err(|_| crate::SecureStoreError::Unavailable)?;
    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn decrypt(
    anchor_key: &[u8],
    profile: [u8; 32],
    database: [u8; 32],
    aad: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, crate::SecureStoreError> {
    if envelope.len() < NONCE_LEN + aead::AES_256_GCM.tag_len() {
        return Err(crate::SecureStoreError::InvalidSeal);
    }
    let key_bytes = derive(anchor_key, profile, database)?;
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes.as_ref())
        .map_err(|_| crate::SecureStoreError::Unavailable)?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce_bytes: [u8; NONCE_LEN] = envelope[..NONCE_LEN]
        .try_into()
        .map_err(|_| crate::SecureStoreError::InvalidSeal)?;
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| crate::SecureStoreError::InvalidSeal)?;
    let mut ciphertext = Zeroizing::new(envelope[NONCE_LEN..].to_vec());
    let plaintext = key
        .open_in_place(nonce, aead::Aad::from(aad), &mut ciphertext)
        .map_err(|_| crate::SecureStoreError::InvalidSeal)?;
    let plaintext_len = plaintext.len();
    Ok(Zeroizing::new(ciphertext[..plaintext_len].to_vec()))
}

fn derive(
    anchor_key: &[u8],
    profile: [u8; 32],
    database: [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, crate::SecureStoreError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &profile);
    let prk = salt.extract(anchor_key);
    let info = [KEY_DOMAIN, profile.as_slice(), database.as_slice()];
    let okm = prk
        .expand(&info, AeadKey([0; 32]))
        .map_err(|_| crate::SecureStoreError::Unavailable)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    okm.fill(key.as_mut())
        .map_err(|_| crate::SecureStoreError::Unavailable)?;
    Ok(key)
}
