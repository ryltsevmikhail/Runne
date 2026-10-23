//! Authentication and key derivation: HMAC-SHA-256 proofs, RFC 5869
//! extract/expand (implemented over `hmac` directly), zeroize-on-drop key
//! material (PROTOCOL.md §Handshake). Pure in-memory cryptography: no
//! process execution, no I/O, no dynamic assembly.

use crate::error::ProtocolError;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_PURPOSE: &str = "runne.local-engine.session.v1";
pub const WORKER_PURPOSE: &str = "runne.local-engine.backend.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    C2h,
    H2c,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C2h => "c2h",
            Self::H2c => "h2c",
        }
    }
}

pub fn hmac(secret: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    for part in data {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Purpose-separated extractor input (PROTOCOL.md §Handshake step 3).
pub fn ikm_from_label(secret: &LaunchSecret, ikm_label: &[u8]) -> [u8; 32] {
    hmac(secret.as_bytes(), &[ikm_label])
}

/// RFC 5869 expand step for L=32 output bytes (single block),
/// PRK = 32 bytes.
fn hkdf_expand_32(prk: &[u8; 32], info: &[u8; 27]) -> [u8; 32] {
    hmac(prk, &[info, &[1u8]])
}

/// Zeroize-on-drop launch key material.
#[derive(Clone)]
pub struct LaunchSecret(Box<[u8]>);

impl LaunchSecret {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec().into_boxed_slice())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for LaunchSecret {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

/// Fixed-layout expand context (27 bytes): channel id, epoch counter,
/// direction tag.
pub struct ContextMaterial {
    pub channel: [u8; 16],
    pub epoch: [u8; 8],
    pub tag: [u8; 3],
}

impl ContextMaterial {
    pub fn context_bytes(&self) -> [u8; 27] {
        let mut out = [0u8; 27];
        let mut i = 0;
        for b in &self.channel {
            out[i] = *b;
            i += 1;
        }
        for b in &self.epoch {
            out[i] = *b;
            i += 1;
        }
        for b in &self.tag {
            out[i] = *b;
            i += 1;
        }
        out
    }
}

/// Directional session keys, zeroized on drop.
pub struct SessionKeys {
    c2h: [u8; 32],
    h2c: [u8; 32],
}

impl SessionKeys {
    /// `IKM = ikm_from_label(...)`,
    /// `PRK = HMAC(salt, IKM)` (RFC 5869 extract; salt is already a
    /// 32-byte SHA-256 digest),
    /// `OKM = expand(PRK, session_id || generation_be || direction)` —
    /// one 32-byte block per direction; the direction tag in the context
    /// is set per call (PROTOCOL.md §Handshake step 3).
    pub fn derive(
        secret: &LaunchSecret,
        canonical_hello: &[u8],
        canonical_welcome_without_proof: &[u8],
        context: &ContextMaterial,
        ikm_label: &[u8],
    ) -> Result<Self, ProtocolError> {
        let salt = Sha256::new()
            .chain_update(canonical_hello)
            .chain_update(canonical_welcome_without_proof)
            .finalize();
        let ikm = ikm_from_label(secret, ikm_label);
        let prk = hmac(&salt, &[&ikm]);
        let mut c2h = [0u8; 32];
        let mut h2c = [0u8; 32];
        for (dir, out) in [(Direction::C2h, &mut c2h), (Direction::H2c, &mut h2c)] {
            let tag = dir.as_str().as_bytes();
            let material = ContextMaterial {
                channel: context.channel,
                epoch: context.epoch,
                tag: [tag[0], tag[1], tag[2]],
            };
            let ctx = material.context_bytes();
            let mut info = [0u8; 27];
            info.copy_from_slice(&ctx);
            *out = hkdf_expand_32(&prk, &info);
        }
        Ok(Self { c2h, h2c })
    }

    pub fn key(&self, direction: Direction) -> &[u8; 32] {
        match direction {
            Direction::C2h => &self.c2h,
            Direction::H2c => &self.h2c,
        }
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        for b in self.c2h.iter_mut() {
            *b = 0;
        }
        for b in self.h2c.iter_mut() {
            *b = 0;
        }
    }
}
