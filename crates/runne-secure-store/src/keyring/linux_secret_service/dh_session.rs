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
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use num::FromPrimitive;
use num::bigint::BigUint;
use num::integer::Integer;
use num::traits::{One, Zero};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::port::SsBusError;

/// Secret Service algorithm identifier (identical to the dependency).
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

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
/// The shared key is zeroized on drop; the DH private scalar lives only in a
/// `Zeroizing` local during negotiation. Limitation for reviewers: the
/// intermediate DH shared secret is a `num::BigUint` inside `pow_mod` and
/// cannot be zeroized (no Drop hook in the dependency algorithm either); it
/// is derived from the private scalar only in memory and dropped immediately.
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
        let private = Zeroizing::new(generate_private_key());
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
        let shared_key = Zeroizing::new(derive_shared_key(&private, &server_public)?);
        Ok(Self {
            session_path,
            shared_key,
        })
    }

    /// Encrypts `data` for this session (fresh CSPRNG IV per secret).
    pub fn encrypt(&self, data: &[u8], mime: &str) -> WireSecret {
        let mut iv = [0_u8; 16];
        OsRng.fill_bytes(&mut iv);
        let encrypted =
            encrypt_with_iv(data, &self.shared_key, &iv).expect("valid key and iv lengths");
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

fn generate_private_key() -> [u8; 128] {
    let mut private = [0_u8; 128];
    OsRng.fill_bytes(&mut private);
    private
}

/// Public DH key for one private key (also reused by the test fake peer).
pub fn public_key(private: &[u8; 128]) -> Vec<u8> {
    let modulus = BigUint::from_bytes_be(DH_PRIME);
    let generator = BigUint::from_u64(2).expect("generator 2 is valid");
    pow_mod(&generator, private, &modulus).to_bytes_be()
}

/// Symmetric shared-key derivation (used by both session sides).
pub fn derive_shared_key(private: &[u8; 128], peer_public: &[u8]) -> Result<[u8; 16], SsBusError> {
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
    let shared_bytes = shared.to_bytes_be();
    let mut ikm = vec![0_u8; DH_PRIME.len() - shared_bytes.len()];
    ikm.extend_from_slice(&shared_bytes);
    let mut okm = [0_u8; 16];
    let (_, hk) = hkdf::Hkdf::<Sha256>::extract(None, &ikm);
    hk.expand(&[], &mut okm).expect("16-byte okm is valid");
    Ok(okm)
}

pub fn random_iv() -> [u8; 16] {
    let mut iv = [0_u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

pub fn encrypt_with_iv(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, SsBusError> {
    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    Ok(Aes128CbcEnc::new(key, iv).encrypt_padded_vec_mut::<Pkcs7>(data))
}

pub fn decrypt_with_iv(
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SsBusError> {
    if iv.len() != 16 || data.is_empty() || data.len() % 16 != 0 {
        return Err(SsBusError::Transport);
    }
    let key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(iv);
    Aes128CbcDec::new(key, iv)
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map(Zeroizing::new)
        .map_err(|_| SsBusError::Transport)
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
mod tests {
    use super::*;

    #[test]
    fn known_answer_dh_hkdf_derivation() {
        let private: [u8; 128] = core::array::from_fn(|i| i as u8);
        let server_public = hex::decode(
            "7b1d7d3188d79522e49e1ef8a54a32403fa559965ff46561a8d12fc1f79273e70b2c\
             6ea601992ec15910b87dffa610904bdbc2bdd35b13c95a0d7cb40a0d62720f4a9042\
             59982b507d9981f4eedb7371db1336d26e29d58e2d2da00d7928a64cadc4eb683c0\
             4df21ac4f5f71174805326a640a789679de2fc1b3ed28d2c9ba71",
        )
        .unwrap();
        let key = derive_shared_key(&private, &server_public).unwrap();
        assert_eq!(
            hex::encode(key),
            "17ea7a2ea428d753538424667065cea2",
            "reference vector computed independently from the dependency algorithm"
        );
    }

    #[test]
    fn client_public_key_reference() {
        let private: [u8; 128] = core::array::from_fn(|i| i as u8);
        let modulus = BigUint::from_bytes_be(DH_PRIME);
        let generator = BigUint::from_u64(2).unwrap();
        let public = pow_mod(&generator, &private, &modulus);
        assert_eq!(
            hex::encode(public.to_bytes_be()),
            "a0c1f547ad5dff7b427d7c09796298448f5ef3b2c5000a3222651ecb2f53d2002461\
             9ed31e2d7577628962de190272633d927b9c06a554df61c68bf73c66c181ba1353d7\
             ea6bd55f9fade8394a30477b2e4033e74ec192a33d3b5801caa50430fb874a8bb1c6\
             f2fd121a446c364207a0d6cb18e4dc0c3729879976f261c8396c"
        );
    }

    #[test]
    fn aes_cbc_nist_sp800_38a_known_answer() {
        let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ciphertext = encrypt_with_iv(&plaintext, &key, &iv).unwrap();
        assert_eq!(
            hex::encode(&ciphertext[..16]),
            "7649abac8119b246cee98e9b12e9197d",
            "NIST SP 800-38A F.2.1 first ciphertext block"
        );
        let decrypted = decrypt_with_iv(&ciphertext, &key, &iv).unwrap();
        assert_eq!(&*decrypted, &plaintext);
    }

    #[test]
    fn negotiate_roundtrip_encrypt_decrypt() {
        // Fake OpenSession: derive the "server" public key from a fixed private.
        let server_private: [u8; 128] = core::array::from_fn(|i: usize| ((i * 7 + 3) & 0xff) as u8);
        let modulus = BigUint::from_bytes_be(DH_PRIME);
        let generator = BigUint::from_u64(2).unwrap();
        let server_public = pow_mod(&generator, &server_private, &modulus).to_bytes_be();
        let session = DhSession::negotiate(|_algorithm, _public| {
            Ok((
                server_public,
                "/org/freedesktop/secrets/session/f1".to_owned(),
            ))
        })
        .unwrap();
        let wire = session.encrypt(b"runne secret", "text/plain");
        let clear = session.decrypt(&wire).unwrap();
        assert_eq!(&*clear, b"runne secret");
        // Wrong session path is rejected.
        let mut foreign = session.encrypt(b"x", "text/plain");
        foreign.session_path = "/other".to_owned();
        assert!(session.decrypt(&foreign).is_err());
    }
}
