/// Maximum UTF-8 bytes accepted for one tool argument/result value.
pub const MAX_PROVIDER_TOOL_CONTENT_BYTES: usize = 8 * 1024;
/// Maximum UTF-8 bytes for one normalized tool argument object.
pub const MAX_PROVIDER_TOOL_ARGUMENT_CONTEXT_BYTES: usize = 8 * 1024;
/// Maximum UTF-8 bytes for one serialized tool-result envelope.
pub const MAX_PROVIDER_TOOL_RESULT_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 bytes accepted for a provider-returned tool call identity.
pub const MAX_PROVIDER_TOOL_CALL_ID_BYTES: usize = 128;

/// One of the fixed, explicitly supported workspace tool names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProviderToolNameV1 {
    /// Read a bounded workspace file.
    #[serde(rename = "workspace.file.read")]
    WorkspaceFileRead,
    /// Create a workspace file only when it does not already exist.
    #[serde(rename = "workspace.file.create_new")]
    WorkspaceFileCreateNew,
    /// List bounded paths under the admitted workspace root.
    #[serde(rename = "workspace.files.list")]
    WorkspaceFilesList,
    /// Search literal text in bounded workspace files.
    #[serde(rename = "workspace.files.search")]
    WorkspaceFilesSearch,
    /// Replace a bounded file only against its approved content digest.
    #[serde(rename = "workspace.file.replace")]
    WorkspaceFileReplace,
    /// Execute approved structured argv within the admitted workspace.
    #[serde(rename = "workspace.command.run")]
    WorkspaceCommandRun,
}

impl ProviderToolNameV1 {
    /// Returns the exact provider-visible function name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceFileRead => "workspace.file.read",
            Self::WorkspaceFileCreateNew => "workspace.file.create_new",
            Self::WorkspaceFilesList => "workspace.files.list",
            Self::WorkspaceFilesSearch => "workspace.files.search",
            Self::WorkspaceFileReplace => "workspace.file.replace",
            Self::WorkspaceCommandRun => "workspace.command.run",
        }
    }

    /// Returns the provider-safe function identifier used on the wire.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::WorkspaceFileRead => "workspace_file_read",
            Self::WorkspaceFileCreateNew => "workspace_file_create_new",
            Self::WorkspaceFilesList => "workspace_files_list",
            Self::WorkspaceFilesSearch => "workspace_files_search",
            Self::WorkspaceFileReplace => "workspace_file_replace",
            Self::WorkspaceCommandRun => "workspace_command_run",
        }
    }

    /// Maps one exact provider function identifier to its normalized name.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "workspace_file_read" => Some(Self::WorkspaceFileRead),
            "workspace_file_create_new" => Some(Self::WorkspaceFileCreateNew),
            "workspace_files_list" => Some(Self::WorkspaceFilesList),
            "workspace_files_search" => Some(Self::WorkspaceFilesSearch),
            "workspace_file_replace" => Some(Self::WorkspaceFileReplace),
            "workspace_command_run" => Some(Self::WorkspaceCommandRun),
            _ => None,
        }
    }

    /// Returns the immutable JSON schema for this function's arguments.
    pub fn parameters(self) -> Value {
        match self {
            Self::WorkspaceFilesList
            | Self::WorkspaceFilesSearch
            | Self::WorkspaceFileReplace
            | Self::WorkspaceCommandRun => coding_tool_parameters(self),
            Self::WorkspaceFileRead => serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string", "maxLength": 255}},
                "required": ["path"],
                "additionalProperties": false
            }),
            Self::WorkspaceFileCreateNew => serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "maxLength": 255},
                    "content_base64": {"type": "string", "maxLength": 8192}
                },
                "required": ["path", "content_base64"],
                "additionalProperties": false
            }),
        }
    }
}

/// Exact immutable declaration of one supported workspace function.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProviderToolDeclarationV1 {
    name: ProviderToolNameV1,
    parameters: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolDeclaration {
    name: ProviderToolNameV1,
    parameters: Value,
}

impl<'de> Deserialize<'de> for ProviderToolDeclarationV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawToolDeclaration::deserialize(deserializer)?;
        Self::new(raw.name, raw.parameters).map_err(serde::de::Error::custom)
    }
}

impl ProviderToolDeclarationV1 {
    /// Builds the fixed schema declaration for a supported function.
    pub fn for_name(name: ProviderToolNameV1) -> Self {
        Self {
            name,
            parameters: name.parameters(),
        }
    }

    fn new(name: ProviderToolNameV1, parameters: Value) -> Result<Self, &'static str> {
        if parameters != name.parameters() {
            return Err("tool schema differs from the fixed declaration");
        }
        Ok(Self { name, parameters })
    }

    /// Returns the exact provider-visible function name.
    pub const fn name(&self) -> ProviderToolNameV1 {
        self.name
    }
    /// Returns the exact immutable argument schema.
    pub const fn parameters(&self) -> &Value {
        &self.parameters
    }
}

/// Correlated bounded output from one previously committed tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderToolResultV1 {
    call_id: String,
    name: ProviderToolNameV1,
    arguments_json: String,
    output: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolResult {
    call_id: String,
    name: ProviderToolNameV1,
    arguments_json: String,
    output: String,
}

impl<'de> Deserialize<'de> for ProviderToolResultV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawToolResult::deserialize(deserializer)?;
        Self::new(raw.call_id, raw.name, raw.arguments_json, raw.output)
            .map_err(serde::de::Error::custom)
    }
}

impl ProviderToolResultV1 {
    /// Creates one bounded provider function result with exact call correlation.
    pub fn new(
        call_id: String,
        name: ProviderToolNameV1,
        arguments_json: String,
        output: String,
    ) -> Result<Self, &'static str> {
        if call_id.is_empty() || call_id.len() > MAX_PROVIDER_TOOL_CALL_ID_BYTES {
            return Err("tool call identity is empty or too long");
        }
        if output.len() > MAX_PROVIDER_TOOL_RESULT_BYTES {
            return Err("tool result envelope exceeds 16 KiB");
        }
        if arguments_json.len() > MAX_PROVIDER_TOOL_ARGUMENT_CONTEXT_BYTES {
            return Err("tool arguments exceed 8 KiB");
        }
        Ok(Self {
            call_id,
            name,
            arguments_json,
            output,
        })
    }

    /// Returns the exact provider call identity.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
    /// Returns the exact supported function name.
    pub const fn name(&self) -> ProviderToolNameV1 {
        self.name
    }
    /// Returns the exact bounded arguments emitted by the provider.
    pub fn arguments_json(&self) -> &str {
        &self.arguments_json
    }
    /// Returns the bounded provider-visible output envelope.
    pub fn output(&self) -> &str {
        &self.output
    }
}
