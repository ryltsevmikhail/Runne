use core::fmt;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use thiserror::Error;

/// Maximum byte length of a tool identity.
pub const MAX_TOOL_ID_BYTES: usize = 128;
/// Maximum canonical JSON bytes for one tool schema.
pub const MAX_TOOL_SCHEMA_BYTES: usize = 65_536;

/// Rejected tool identity or version.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidToolIdentity {
    /// Value was empty.
    #[error("tool identity is empty")]
    Empty,
    /// Value exceeded its byte limit.
    #[error("tool identity is too long: max={max}, actual={actual}")]
    TooLong {
        /// Maximum accepted bytes.
        max: usize,
        /// Actual bytes.
        actual: usize,
    },
    /// Value contains a control or non-ASCII character.
    #[error("tool identity contains an invalid character")]
    InvalidCharacter,
    /// Version is not exact `major.minor.patch`.
    #[error("tool version must be exact major.minor.patch")]
    InvalidVersion,
}

/// Stable bounded tool identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolId(String);

impl ToolId {
    /// Constructs a printable bounded ASCII identity.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidToolIdentity> {
        let value = value.into();
        if value.is_empty() {
            return Err(InvalidToolIdentity::Empty);
        }
        if value.len() > MAX_TOOL_ID_BYTES {
            return Err(InvalidToolIdentity::TooLong {
                max: MAX_TOOL_ID_BYTES,
                actual: value.len(),
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(InvalidToolIdentity::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the identity text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact three-component tool version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl ToolVersion {
    /// Parses exact numeric `major.minor.patch` without prerelease aliases.
    pub fn new(value: &str) -> Result<Self, InvalidToolIdentity> {
        let parts = value.split('.').collect::<Vec<_>>();
        if parts.len() != 3
            || parts.iter().any(|part| {
                part.is_empty()
                    || (part.len() > 1 && part.starts_with('0'))
                    || !part.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(InvalidToolIdentity::InvalidVersion);
        }
        Ok(Self {
            major: parts[0]
                .parse()
                .map_err(|_| InvalidToolIdentity::InvalidVersion)?,
            minor: parts[1]
                .parse()
                .map_err(|_| InvalidToolIdentity::InvalidVersion)?,
            patch: parts[2]
                .parse()
                .map_err(|_| InvalidToolIdentity::InvalidVersion)?,
        })
    }
}

impl fmt::Display for ToolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Exact immutable tool identity and version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolRef {
    tool_id: ToolId,
    version: ToolVersion,
}

impl ToolRef {
    /// Constructs an exact tool reference.
    pub const fn new(tool_id: ToolId, version: ToolVersion) -> Self {
        Self { tool_id, version }
    }

    /// Returns the tool identity.
    pub const fn tool_id(&self) -> &ToolId {
        &self.tool_id
    }

    /// Returns the exact version.
    pub const fn version(&self) -> ToolVersion {
        self.version
    }
}

/// Tool execution class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolClass {
    /// Selected built-in process operation.
    BuiltInProcess,
    /// Brokered filesystem operation.
    BuiltInFilesystem,
    /// Brokered network operation.
    BuiltInNetwork,
    /// Out-of-process plugin tool.
    Plugin,
    /// Local MCP tool.
    McpLocal,
    /// Remote MCP tool.
    McpRemote,
}

/// Declarative containment profile required by a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxProfile {
    /// Restricted process tree.
    ProcessRestricted,
    /// Workspace coding filesystem boundary.
    WorkspaceCoding,
    /// Restricted network broker.
    NetworkRestricted,
    /// Plugin host containment.
    PluginHost,
    /// Local MCP containment.
    McpLocal,
}

/// Invalid immutable tool definition.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidToolDefinition {
    /// Schema exceeds the exact byte bound.
    #[error("tool schema is too large")]
    SchemaTooLarge,
    /// JSON Schema Draft 2020-12 compilation failed.
    #[error("tool schema is invalid")]
    InvalidSchema,
}

/// Immutable versioned tool definition.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDefinition {
    tool_ref: ToolRef,
    class: ToolClass,
    input_schema: Value,
    sandbox_profile: SandboxProfile,
}

impl ToolDefinition {
    /// Constructs and validates an immutable Draft 2020-12 definition.
    pub fn new(
        tool_id: ToolId,
        version: ToolVersion,
        class: ToolClass,
        input_schema: Value,
        sandbox_profile: SandboxProfile,
    ) -> Result<Self, InvalidToolDefinition> {
        let bytes =
            serde_json::to_vec(&input_schema).map_err(|_| InvalidToolDefinition::InvalidSchema)?;
        if bytes.len() > MAX_TOOL_SCHEMA_BYTES {
            return Err(InvalidToolDefinition::SchemaTooLarge);
        }
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&input_schema)
            .map_err(|_| InvalidToolDefinition::InvalidSchema)?;
        Ok(Self {
            tool_ref: ToolRef::new(tool_id, version),
            class,
            input_schema,
            sandbox_profile,
        })
    }

    /// Returns the exact immutable reference.
    pub const fn tool_ref(&self) -> &ToolRef {
        &self.tool_ref
    }

    /// Returns the execution class.
    pub const fn class(&self) -> ToolClass {
        self.class
    }

    /// Returns the declarative containment profile.
    pub const fn sandbox_profile(&self) -> SandboxProfile {
        self.sandbox_profile
    }

    pub(crate) const fn input_schema(&self) -> &Value {
        &self.input_schema
    }
}

/// Exact tool references captured at attempt start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsetSnapshot {
    tool_refs: Vec<ToolRef>,
}

impl ToolsetSnapshot {
    pub(crate) fn new(tool_refs: Vec<ToolRef>) -> Self {
        Self { tool_refs }
    }

    /// Returns sorted exact tool references.
    pub fn tool_refs(&self) -> &[ToolRef] {
        &self.tool_refs
    }
}
