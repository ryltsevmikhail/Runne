//! Internal DH Secret Service session crypto, unique-name bound.
//!
//! Faithful port of the session negotiation and secret encryption used by the
//! already-locked `dbus-secret-service 4.1.0` dependency (MIT OR Apache-2.0,
//! `src/session.rs` crypto module). The dependency hardcodes well-known
//! destinations for every proxy, so the Linux facade cannot reuse its private
//! session object; this port keeps the exact wire algorithm while the facade
//! binds every call (including `OpenSession`) to the resolved owner unique
//! name. Only deliberate deviation: key and IV entropy comes from the OS CSPRNG
//! instead of the dependency's `fastrand` PRNG — same wire format, strictly
//! stronger randomness. TD-1 does not authorize any transport downgrade.
//!
//! Classification: Target (this slice); Observed (dependency algorithm facts).

use std::ops::{Mul, Rem, Shr};

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use num::FromPrimitive;
use num::bigint::BigUint;
use num::integer::Integer;
use num::traits::{One, Zero};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::provider_credential::MAX_ENCODED_PROVIDER_CREDENTIAL_BYTES;

use super::port::SsBusError;

/// Secret Service algorithm identifier (identical to the dependency).
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
const AES_BLOCK_BYTES: usize = 16;
const MAX_CIPHERTEXT_BYTES: usize =
    (MAX_ENCODED_PROVIDER_CREDENTIAL_BYTES / AES_BLOCK_BYTES + 1) * AES_BLOCK_BYTES;

const DH_PRIME: &[u8; 128] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// One negotiated encrypted Secret Service session.
///
/// The shared key is zeroized on drop. Repository-owned scalar and HKDF byte
/// buffers use `Zeroizing`; `pow_mod` also creates dependency-owned `BigUint`
/// copies of the private exponent and shared secret. The `num` types expose no
/// wipe hook, so their allocations are outside this code's zeroization control.
/// The HKDF implementation's internal state is likewise not exposed for wipe.
pub struct DhSession {
    pub session_path: String,
    shared_key: Zeroizing<[u8; 16]>,
}

/// Wire form of one secret as transferred over the session.
pub struct WireSecret {
    pub session_path: String,
    pub iv: Vec<u8>,
    pub data: Vec<u8>,
    pub mime: String,
}

impl DhSession {
    /// Negotiates one session: sends our public key, receives the peer public
    /// key and the negotiated session object path.
    pub fn negotiate(
        open_session: impl FnOnce(&str, Vec<u8>) -> Result<(Vec<u8>, String), SsBusError>,
    ) -> Result<Self, SsBusError> {
        let private = generate_private_key();
        let modulus = BigUint::from_bytes_be(DH_PRIME);
        let generator = BigUint::from_u64(2).ok_or(SsBusError::Transport)?;
        let public = pow_mod(&generator, &*private, &modulus);
        let (server_public, session_path) = open_session(ALGORITHM_DH, public.to_bytes_be())?;
        // Peer-element validation before any derivation: public key must be a
        // non-empty big-endian integer strictly below the 1024-bit prime;
        // the session object path must be a bounded absolute D-Bus path.
        if server_public.is_empty() || server_public.len() > DH_PRIME.len() {
            return Err(SsBusError::Transport);
        }
        if !is_valid_session_path(&session_path) {
            return Err(SsBusError::Transport);
        }
        let shared_key = derive_shared_key_zeroizing(&private, &server_public)?;
        Ok(Self {
            session_path,
            shared_key,
        })
    }

    /// Encrypts `data` for this session (fresh CSPRNG IV per secret).
    pub fn encrypt(&self, data: &[u8], mime: &str) -> WireSecret {
        let mut iv = [0_u8; 16];
        OsRng.fill_bytes(&mut iv);
        let encrypted = encrypt_with_iv(data, &self.shared_key, &iv);
        WireSecret {
            session_path: self.session_path.clone(),
            iv: iv.to_vec(),
            data: encrypted,
            mime: mime.to_owned(),
        }
    }

    /// Decrypts one wire secret for this session.
    pub fn decrypt(&self, secret: &WireSecret) -> Result<Zeroizing<Vec<u8>>, SsBusError> {
        if secret.session_path != self.session_path {
            return Err(SsBusError::Transport);
        }
        decrypt_with_iv(&secret.data, &self.shared_key, &secret.iv)
    }
}

fn generate_private_key() -> Zeroizing<[u8; 128]> {
    let mut private = Zeroizing::new([0_u8; 128]);
    OsRng.fill_bytes(&mut *private);
    private
}

/// Public DH key for one private key (also reused by the test fake peer).
#[cfg(test)]
pub fn public_key(private: &[u8; 128]) -> Vec<u8> {
    let modulus = BigUint::from_bytes_be(DH_PRIME);
    let generator = BigUint::from_u64(2).expect("generator 2 is valid");
    pow_mod(&generator, private, &modulus).to_bytes_be()
}

/// Symmetric shared-key derivation (used by both session sides).
fn derive_shared_key_zeroizing(
    private: &[u8; 128],
    peer_public: &[u8],
) -> Result<Zeroizing<[u8; 16]>, SsBusError> {
    if peer_public.is_empty() || peer_public.len() > DH_PRIME.len() {
        return Err(SsBusError::Transport);
    }
    let modulus = BigUint::from_bytes_be(DH_PRIME);
    let peer = BigUint::from_bytes_be(peer_public);
    let trivial_subgroup = peer.is_zero() || peer.is_one() || peer == modulus.clone() - 1_u32;
    if peer >= modulus || trivial_subgroup {
        return Err(SsBusError::Transport);
    }
    let shared = pow_mod(&peer, private, &modulus);
    let shared_bytes = Zeroizing::new(shared.to_bytes_be());
    let mut ikm = Zeroizing::new([0_u8; DH_PRIME.len()]);
    let shared_offset = ikm.len() - shared_bytes.len();
    ikm[shared_offset..].copy_from_slice(&shared_bytes);
    let mut okm = Zeroizing::new([0_u8; 16]);
    let (mut prk, hk) = hkdf::Hkdf::<Sha256>::extract(None, &ikm[..]);
    hk.expand(&[], &mut *okm).expect("16-byte okm is valid");
    prk.zeroize();
    Ok(okm)
}

#[cfg(test)]
pub fn derive_shared_key(private: &[u8; 128], peer_public: &[u8]) -> Result<[u8; 16], SsBusError> {
    derive_shared_key_zeroizing(private, peer_public).map(|key| *key)
}

#[cfg(test)]
pub fn random_iv() -> [u8; 16] {
    let mut iv = [0_u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

pub fn encrypt_with_iv(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let capacity = data.len().saturating_add(AES_BLOCK_BYTES);
    let mut output = Zeroizing::new(vec![0; capacity]);
    let ciphertext_len = Aes128CbcEnc::new_from_slices(key, iv)
        .expect("AES128 key and IV are exactly 16 bytes")
        .encrypt_padded_b2b::<Pkcs7>(data, &mut output)
        .expect("output reserves one full PKCS#7 block")
        .len();
    output.truncate(ciphertext_len);
    std::mem::take(&mut *output)
}

pub fn decrypt_with_iv(
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SsBusError> {
    if iv.len() != AES_BLOCK_BYTES
        || data.is_empty()
        || !data.len().is_multiple_of(AES_BLOCK_BYTES)
        || data.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(SsBusError::Transport);
    }
    let mut plaintext = Zeroizing::new(data.to_vec());
    let plaintext_len = decrypt_padded_in_place(&mut plaintext, key, iv)?;
    plaintext.truncate(plaintext_len);
    Ok(plaintext)
}

fn decrypt_padded_in_place(
    buffer: &mut Zeroizing<Vec<u8>>,
    key: &[u8; 16],
    iv: &[u8],
) -> Result<usize, SsBusError> {
    if iv.len() != AES_BLOCK_BYTES
        || buffer.is_empty()
        || !buffer.len().is_multiple_of(AES_BLOCK_BYTES)
    {
        buffer.zeroize();
        return Err(SsBusError::Transport);
    }
    let plaintext_len = if let Ok(plaintext) = Aes128CbcDec::new_from_slices(key, iv)
        .expect("key is 16 bytes and IV length was validated")
        .decrypt_padded::<Pkcs7>(buffer)
    {
        plaintext.len()
    } else {
        buffer.zeroize();
        return Err(SsBusError::Transport);
    };
    buffer[plaintext_len..].zeroize();
    Ok(plaintext_len)
}

fn is_valid_session_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && path.starts_with('/')
        && path.bytes().all(|byte| byte.is_ascii_graphic())
}

fn pow_mod(base: &BigUint, exponent: &[u8], modulus: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exponent = BigUint::from_bytes_be(exponent);
    let mut result: BigUint = One::one();
    while !exponent.is_zero() {
        if exponent.is_odd() {
            result = result.mul(&base).rem(modulus);
        }
        exponent = exponent.shr(1);
        base = (&base).mul(&base).rem(modulus);
    }
    result
}

impl Drop for DhSession {
    fn drop(&mut self) {
        self.shared_key.zeroize();
    }
}

#[cfg(test)]
#[path = "tests/dh_session.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/cbc_compatibility.rs"]
mod cbc_compatibility;

#[cfg(test)]
#[path = "tests/cbc_zeroize.rs"]
mod cbc_zeroize;
