use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

const MAX_STATE: usize = 256;

/// Bounded PKCE verifier and S256 challenge.
#[derive(Clone, PartialEq, Eq)]
pub struct PkcePair {
    verifier: String,
    challenge: String,
}
impl std::fmt::Debug for PkcePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkcePair")
            .field("verifier", &"[REDACTED]")
            .field("challenge", &self.challenge)
            .finish()
    }
}
impl PkcePair {
    /// Generates a fresh verifier using the OS random source.
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
    /// Returns the verifier for the token request.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }
    /// Returns the S256 challenge for authorization.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

/// State validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StateError {
    /// State value was absent or oversized.
    #[error("OAuth state is invalid")]
    Invalid,
    /// Callback state did not match.
    #[error("OAuth state mismatch")]
    Mismatch,
}

/// Generates a bounded opaque callback state.
pub fn generate_state() -> Result<String, StateError> {
    let mut bytes = [0_u8; 24];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| StateError::Invalid)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
/// Compares callback state in constant time after bounds checking.
pub fn verify_state(expected: &str, received: &str) -> Result<(), StateError> {
    if expected.is_empty()
        || received.is_empty()
        || expected.len() > MAX_STATE
        || received.len() > MAX_STATE
    {
        return Err(StateError::Invalid);
    }
    if expected.as_bytes().ct_eq(received.as_bytes()).into() {
        Ok(())
    } else {
        Err(StateError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pkce_and_state_are_bounded() {
        let pair = PkcePair::generate();
        assert!(!pair.verifier().is_empty());
        assert_eq!(pair.challenge().len(), 43);
        assert!(verify_state("s", "x").is_err());
        assert!(verify_state("s", "s").is_ok());
        assert!(verify_state("", "s").is_err());
    }
}
