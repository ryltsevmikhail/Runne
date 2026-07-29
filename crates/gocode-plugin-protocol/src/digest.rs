//! Role-separated digest newtypes — compiler-enforced disambiguation.
//!
//! Each digest role is its own type, preventing accidental interchange
//! of profile, schema, contract, manifest, and payload digests.

use core::fmt;

// ── Digest newtype macro ──────────────────────────────────────────────────

macro_rules! digest_newtype {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(0x", stringify!($name))?;
                for b in &self.0 {
                    write!(f, "{:02x}", b)?;
                }
                write!(f, ")")
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in &self.0 {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    };
}

// ── Digest newtypes ───────────────────────────────────────────────────────

digest_newtype!(Sha256Digest, "Raw SHA-256 output (32 bytes).");
digest_newtype!(
    BootstrapSchemaDigest,
    "Digest of the bootstrap message schema."
);
digest_newtype!(
    WireContractDigest,
    "Digest of the wire contract specification."
);
digest_newtype!(SchemaBundleDigest, "Digest of the session schema bundle.");
digest_newtype!(BoundsProfileDigest, "Digest of a BoundsProfile definition.");
digest_newtype!(
    ProfileDigest,
    "Digest of a ProtocolSupportProfile definition."
);
digest_newtype!(ManifestDigest, "Digest of the plugin manifest.");
digest_newtype!(MessageDigest, "Digest of a single message payload.");
digest_newtype!(PayloadDigest, "Digest of a raw invocation payload.");
digest_newtype!(
    ProtocolNegotiationSnapshotDigest,
    "Digest of the negotiation snapshot."
);

// ── DigestAlgorithm ───────────────────────────────────────────────────────

/// Identifies the hash algorithm used for a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-256 (32-byte output).
    Sha256,
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => write!(f, "sha256"),
        }
    }
}

// ── PackageDigest ─────────────────────────────────────────────────────────

/// Algorithm-tagged digest for package content-addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PackageDigest {
    pub(crate) algorithm: DigestAlgorithm,
    pub(crate) bytes: [u8; 32],
}

impl PackageDigest {
    pub const fn new(algorithm: DigestAlgorithm, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }

    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Display for PackageDigest {
    /// Algorithm-tagged representation: `sha256:hex...`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.algorithm)?;
        for b in &self.bytes {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

// ── Sha256Provider trait ──────────────────────────────────────────────────

/// External SHA-256 provider — protocol crate stores/comparses typed digests
/// but does not implement hashing itself.
pub trait Sha256Provider {
    /// Compute the SHA-256 digest of `data`.
    fn sha256(&self, data: &[u8]) -> Sha256Digest;
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_newtypes_are_distinct() {
        let a = Sha256Digest::from_bytes([0; 32]);
        let b = BootstrapSchemaDigest::from_bytes([0; 32]);
        // Compile-time check: cannot assign one to the other
        // Runtime check: same bytes, different types
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn test_digest_display_64_chars() {
        let d = ProfileDigest::from_bytes([0xab; 32]);
        let s = d.to_string();
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn test_package_digest_display() {
        let pd = PackageDigest::new(DigestAlgorithm::Sha256, [0x42; 32]);
        let s = pd.to_string();
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.len(), 7 + 64);
    }
}
