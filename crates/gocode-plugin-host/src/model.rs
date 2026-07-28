use core::fmt;

const MAX_PLUGIN_IDENTIFIER_LENGTH: usize = 128;

/// Failure to construct a bounded plugin identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPluginIdentifier {
    /// The identifier was empty.
    Empty,
    /// The identifier exceeded its maximum byte length.
    TooLong {
        /// Maximum permitted byte length.
        max: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// The identifier contained a control character.
    InvalidCharacter,
}

impl fmt::Display for InvalidPluginIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("plugin identifier must not be empty"),
            Self::TooLong { max, actual } => {
                write!(
                    formatter,
                    "plugin identifier exceeds {max} bytes (got {actual})"
                )
            }
            Self::InvalidCharacter => {
                formatter.write_str("plugin identifier must not contain control characters")
            }
        }
    }
}

impl std::error::Error for InvalidPluginIdentifier {}

macro_rules! bounded_plugin_identifier {
    ($name:ident, $docs:literal) => {
        #[doc = $docs]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Creates an identifier after enforcing bounded, printable input.
            pub fn new(value: impl Into<String>) -> Result<Self, InvalidPluginIdentifier> {
                let value = value.into();
                if value.is_empty() {
                    return Err(InvalidPluginIdentifier::Empty);
                }
                if value.len() > MAX_PLUGIN_IDENTIFIER_LENGTH {
                    return Err(InvalidPluginIdentifier::TooLong {
                        max: MAX_PLUGIN_IDENTIFIER_LENGTH,
                        actual: value.len(),
                    });
                }
                if value.chars().any(char::is_control) {
                    return Err(InvalidPluginIdentifier::InvalidCharacter);
                }
                Ok(Self(value))
            }

            /// Returns the validated identifier text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

bounded_plugin_identifier!(
    PluginHostProfileId,
    "Bounded immutable plugin-host profile identity."
);
bounded_plugin_identifier!(PluginActivationId, "Bounded plugin activation identity.");
bounded_plugin_identifier!(PluginHookId, "Bounded plugin hook identity.");
bounded_plugin_identifier!(
    PluginHookInvocationId,
    "Bounded plugin hook invocation identity."
);

/// Monotonic plugin activation generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginGeneration(u64);

impl PluginGeneration {
    /// The first valid plugin generation.
    pub const INITIAL: Self = Self(1);

    /// Constructs a non-zero generation.
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Returns the numeric generation value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Fixed-size content digest used by plugin authority records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginDigest([u8; 32]);

impl PluginDigest {
    /// Constructs a digest from exactly 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-size digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Plugin class declared by the package manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginClass {
    /// General extension hook package.
    Extension,
    /// Security-sensitive hook package.
    Security,
}

/// Registry-derived trust tier, never asserted by a package source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginTrust {
    /// The registry verified the provenance and policy binding.
    RegistryVerified,
    /// The registry admitted the package under a restricted policy.
    Restricted,
}
