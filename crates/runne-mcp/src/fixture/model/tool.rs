/// Bounded immutable tool definition used only by the deterministic fixture.
#[derive(Clone, PartialEq)]
pub struct FixtureTool {
    name: String,
    version: String,
    description: String,
    input_schema: Value,
    output_schema: Value,
    execution_class: crate::McpToolExecutionClass,
}

impl FixtureTool {
    /// Creates one closed-subset fixture tool definition.
    pub fn new(
        name: impl Into<String>, version: impl Into<String>, description: impl Into<String>,
        input_schema: Value, output_schema: Value,
    ) -> Result<Self, FixtureMcpFailure> {
        Self::new_with_execution_class(
            name,
            version,
            description,
            input_schema,
            output_schema,
            crate::McpToolExecutionClass::ProtocolOnly,
        )
    }

    /// Creates one closed-subset fixture tool that requires the process contract.
    pub fn new_process_backed(
        name: impl Into<String>, version: impl Into<String>, description: impl Into<String>,
        input_schema: Value, output_schema: Value,
    ) -> Result<Self, FixtureMcpFailure> {
        Self::new_with_execution_class(
            name,
            version,
            description,
            input_schema,
            output_schema,
            crate::McpToolExecutionClass::ProcessBacked,
        )
    }

    fn new_with_execution_class(
        name: impl Into<String>, version: impl Into<String>, description: impl Into<String>,
        input_schema: Value, output_schema: Value, execution_class: crate::McpToolExecutionClass,
    ) -> Result<Self, FixtureMcpFailure> {
        let name = checked_tool_name(name.into())?;
        let version = checked_text(version.into())?;
        let description = checked_description(description.into())?;
        super::schema::validate_schema(&input_schema)?;
        super::schema::validate_schema(&output_schema)?;
        Ok(Self { name, version, description, input_schema, output_schema, execution_class })
    }

    pub(crate) fn name(&self) -> &str { &self.name }
    pub(crate) fn version(&self) -> &str { &self.version }
    pub(crate) fn input_schema(&self) -> &Value { &self.input_schema }
    pub(crate) fn output_schema(&self) -> &Value { &self.output_schema }
    pub(crate) const fn execution_class(&self) -> crate::McpToolExecutionClass { self.execution_class }
    pub(crate) fn definition_digest(&self) -> [u8; 32] {
        let execution_class = match self.execution_class {
            crate::McpToolExecutionClass::ProtocolOnly => b"protocol-only".as_slice(),
            crate::McpToolExecutionClass::ProcessBacked => b"process-backed".as_slice(),
        };
        digest_domain(b"RUNNE_MCP_FIXTURE_TOOL_V1\0", &[
            self.name.as_bytes(), self.version.as_bytes(), self.description.as_bytes(),
            &serde_json::to_vec(&self.input_schema).expect("serde_json::Value always serializes"),
            &serde_json::to_vec(&self.output_schema).expect("serde_json::Value always serializes"),
            execution_class,
        ])
    }
}
