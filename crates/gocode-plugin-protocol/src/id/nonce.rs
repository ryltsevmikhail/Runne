// ── Nonce ─────────────────────────────────────────────────────────────────

/// 16-byte random nonce for bootstrap handshake replay protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 16]);

impl Nonce {
    /// Create a nonce from raw 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    /// Borrow the inner 16-byte array.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

// ── Bounded string newtype macro ──────────────────────────────────────────

macro_rules! bounded_id_string {
    ($name:ident, $max:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Max byte length.
            pub const MAX_BYTES: usize = $max;

            /// Create a new bounded string identifier.
            pub fn new(s: impl Into<String>) -> Result<Self, InvalidWireIdReason> {
                let s = s.into();
                if s.is_empty() {
                    return Err(InvalidWireIdReason::Empty);
                }
                let len = s.len();
                if len > $max {
                    return Err(InvalidWireIdReason::TooLong {
                        max: $max,
                        actual: len,
                    });
                }
                if s.as_bytes().iter().any(|&b| b < 0x20 || b == 0x7f) {
                    return Err(InvalidWireIdReason::InvalidCharacter);
                }
                Ok(Self(s))
            }

            /// Return the inner string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

bounded_id_string!(
    PluginId,
    128,
    "Plugin package identity (e.g. 'com.example.my-plugin')."
);
bounded_id_string!(TargetIdentity, 128, "Target identity for plugin execution.");
bounded_id_string!(
    EntrypointIdentity,
    256,
    "Entrypoint identity within a plugin."
);
bounded_id_string!(PluginIdentity, 128, "Plugin runtime identity.");
bounded_id_string!(MigrationIdentity, 128, "Migration execution identity.");
bounded_id_string!(ProfileId, 128, "Protocol profile identifier.");
bounded_id_string!(PluginVersion, 64, "Plugin version string (semver).");
