// ── ProtocolVersion ───────────────────────────────────────────────────────

/// Protocol version tuple. V1 begins at 1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Protocol version 1.0.
    pub const V1_0: Self = Self { major: 1, minor: 0 };

    /// Create a new protocol version with the given major and minor numbers.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
    /// Return the major version number.
    pub const fn major(&self) -> u16 {
        self.major
    }
    /// Return the minor version number.
    pub const fn minor(&self) -> u16 {
        self.minor
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ── SchemaRevision / MessageTypeId / DeadlineUnixMillis ───────────────────

/// Monotonic schema revision number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaRevision(u32);

impl SchemaRevision {
    /// Create a new schema revision from a raw u32.
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
    /// Return the inner u32 value.
    pub const fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for SchemaRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Message type identifier — maps to a specific schema/type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageTypeId(u32);

impl MessageTypeId {
    /// Create a new message type identifier from a raw u32.
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
    /// Return the inner u32 value.
    pub const fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for MessageTypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unix epoch milliseconds deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeadlineUnixMillis(u64);

impl DeadlineUnixMillis {
    /// Create a new deadline from a raw u64 (Unix epoch milliseconds).
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// Return the inner u64 value.
    pub const fn value(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for DeadlineUnixMillis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
