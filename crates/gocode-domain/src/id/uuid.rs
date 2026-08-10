// ── UUIDv7 helper ──────────────────────────────────────────────────────────

/// Parse a UUIDv7 string into `[u8; 16]`, validating format, version (7),
/// and variant (`10xx`).
///
/// No external dependencies — manual hex parsing.
pub(crate) fn parse_uuid_v7(s: &str) -> Result<[u8; 16], InvalidIdReason> {
    if s.is_empty() {
        return Err(InvalidIdReason::Empty);
    }
    if s.len() != 36 {
        return Err(InvalidIdReason::InvalidUuidFormat);
    }
    let b = s.as_bytes();
    // Check hyphens at positions 8, 13, 18, 23
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return Err(InvalidIdReason::InvalidUuidFormat);
    }
    // Parse 32 hex nibbles → 16 bytes
    let mut out = [0u8; 16];
    let mut byte_idx = 0usize;
    let mut chars = s.chars().filter(|c| *c != '-');
    while byte_idx < 16 {
        let hi = chars.next().ok_or(InvalidIdReason::InvalidUuidFormat)?;
        let lo = chars.next().ok_or(InvalidIdReason::InvalidUuidFormat)?;
        let hi_val = hex_nibble(hi as u8).ok_or(InvalidIdReason::InvalidUuidFormat)?;
        let lo_val = hex_nibble(lo as u8).ok_or(InvalidIdReason::InvalidUuidFormat)?;
        out[byte_idx] = (hi_val << 4) | lo_val;
        byte_idx += 1;
    }
    validate_uuid_v7_bytes(&out)?;
    Ok(out)
}

/// Validate UUIDv7 version and RFC 9562 variant bits in raw UUID bytes.
pub fn validate_uuid_v7_bytes(bytes: &[u8; 16]) -> Result<(), InvalidIdReason> {
    // Version: upper nibble of byte 6 must be 0x7
    let version = bytes[6] >> 4;
    if version != 7 {
        return Err(InvalidIdReason::InvalidUuidVersion {
            expected: 7,
            actual: version,
        });
    }
    // Variant: top 2 bits of byte 8 must be 0b10
    let variant = bytes[8] >> 6;
    if variant != 0b10 {
        return Err(InvalidIdReason::InvalidUuidVariant);
    }
    Ok(())
}

/// Interpret a byte as a hex nibble value.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Format a `[u8; 16]` as a standard 8-4-4-4-12 UUID string.
pub(crate) fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

// ── Macro for UUIDv7 newtype generation ────────────────────────────────────

macro_rules! uuid_v7_newtype {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
        )]
        pub struct $name([u8; 16]);

        impl $name {
            /// Create from raw bytes. Caller must ensure bytes are a valid UUIDv7.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Return a reference to the raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Consume and return the raw bytes.
            pub const fn into_bytes(self) -> [u8; 16] {
                self.0
            }

            /// Parses a UUIDv7 string into this typed identifier.
            pub fn parse(value: &str) -> Result<Self, InvalidIdReason> {
                value.parse()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&$crate::id::format_uuid(&self.0))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", $crate::id::format_uuid(&self.0))
            }
        }

        impl std::str::FromStr for $name {
            type Err = InvalidIdReason;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytes = $crate::id::parse_uuid_v7(s)?;
                Ok(Self(bytes))
            }
        }
    };
}

pub(crate) use uuid_v7_newtype;

// ── UUIDv7 newtypes ────────────────────────────────────────────────────────

uuid_v7_newtype!(TaskRunId, "UUIDv7 identifier for a task run aggregate.");
uuid_v7_newtype!(
    ConversationId,
    "UUIDv7 identifier for a conversation aggregate."
);
uuid_v7_newtype!(MessageId, "UUIDv7 identifier for a durable message.");
uuid_v7_newtype!(WorkspaceId, "UUIDv7 identifier for a workspace aggregate.");
uuid_v7_newtype!(ProjectId, "UUIDv7 identifier for a project aggregate.");
uuid_v7_newtype!(
    AttemptId,
    "UUIDv7 identifier for a single execution attempt."
);
uuid_v7_newtype!(InvocationId, "UUIDv7 identifier for a plugin invocation.");
uuid_v7_newtype!(CheckpointId, "UUIDv7 identifier for a checkpoint.");
uuid_v7_newtype!(PolicyId, "UUIDv7 identifier for a policy.");
uuid_v7_newtype!(ProcessId, "UUIDv7 identifier for a host process.");
uuid_v7_newtype!(EventId, "UUIDv7 identifier for a domain event.");
uuid_v7_newtype!(CommandId, "UUIDv7 identifier for a command.");

uuid_v7_newtype!(CycleId, "UUIDv7 identifier for a loop cycle.");
uuid_v7_newtype!(StepId, "UUIDv7 identifier for a step outcome.");
uuid_v7_newtype!(PlanId, "UUIDv7 identifier for a plan revision.");
uuid_v7_newtype!(ManifestId, "UUIDv7 identifier for a context manifest.");
uuid_v7_newtype!(ResultId, "UUIDv7 identifier for an immutable result.");
uuid_v7_newtype!(EffectId, "UUIDv7 identifier for a side effect.");
uuid_v7_newtype!(
    BudgetReservationId,
    "UUIDv7 identifier for a budget reservation."
);
uuid_v7_newtype!(SecretRefId, "UUIDv7 identifier for a secret reference.");
uuid_v7_newtype!(
    ContextManifestId,
    "UUIDv7 identifier for a context manifest contract."
);
uuid_v7_newtype!(
    ReconciliationRunId,
    "UUIDv7 identifier for a reconciliation run."
);
uuid_v7_newtype!(PlanEvaluationId, "UUIDv7 identifier for a plan evaluation.");
uuid_v7_newtype!(
    WakeEvidenceId,
    "UUIDv7 identifier for accepted wake evidence."
);
uuid_v7_newtype!(
    EventLogLineageId,
    "UUIDv7 identifier for the event log lineage."
);
uuid_v7_newtype!(
    DaemonInstanceId,
    "UUIDv7 identifier for one daemon process instance."
);
