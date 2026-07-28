use std::collections::BTreeMap;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use thiserror::Error;

use crate::{ToolDefinition, ToolId, ToolRef, ToolsetSnapshot};

/// Successful immutable registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterToolOutcome {
    /// A new exact tool version was registered.
    Registered,
}

/// Tool registry or input-validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ToolRegistryError {
    /// Exact immutable version already exists.
    #[error("duplicate tool version: {0:?}")]
    DuplicateTool(ToolRef),
    /// Exact tool version was not found.
    #[error("tool version was not found: {0:?}")]
    ToolNotFound(ToolRef),
    /// No version exists for a requested snapshot identity.
    #[error("tool identity was not found: {0:?}")]
    ToolIdNotFound(ToolId),
    /// Invocation input does not match the exact schema.
    #[error("tool input schema mismatch")]
    InputSchemaMismatch,
    /// Stored schema unexpectedly failed compilation.
    #[error("tool registry contains an invalid schema")]
    CorruptSchema,
}

/// In-memory immutable tool definition registry.
#[derive(Debug, Default)]
pub struct ToolRegistry {
    definitions: BTreeMap<ToolRef, ToolDefinition>,
}

impl ToolRegistry {
    /// Constructs an empty registry.
    pub const fn new() -> Self {
        Self {
            definitions: BTreeMap::new(),
        }
    }

    /// Registers one exact immutable version.
    pub fn register(
        &mut self,
        definition: ToolDefinition,
    ) -> Result<RegisterToolOutcome, ToolRegistryError> {
        if self.definitions.contains_key(definition.tool_ref()) {
            return Err(ToolRegistryError::DuplicateTool(
                definition.tool_ref().clone(),
            ));
        }
        self.definitions
            .insert(definition.tool_ref().clone(), definition);
        Ok(RegisterToolOutcome::Registered)
    }

    /// Resolves one exact immutable version.
    pub fn resolve(&self, tool_ref: &ToolRef) -> Result<&ToolDefinition, ToolRegistryError> {
        self.definitions
            .get(tool_ref)
            .ok_or_else(|| ToolRegistryError::ToolNotFound(tool_ref.clone()))
    }

    /// Captures latest exact versions for a new attempt.
    pub fn snapshot(&self, tool_ids: &[ToolId]) -> Result<ToolsetSnapshot, ToolRegistryError> {
        let mut refs = Vec::with_capacity(tool_ids.len());
        for tool_id in tool_ids {
            let latest = self
                .definitions
                .keys()
                .filter(|tool_ref| tool_ref.tool_id() == tool_id)
                .max_by_key(|tool_ref| tool_ref.version())
                .cloned()
                .ok_or_else(|| ToolRegistryError::ToolIdNotFound(tool_id.clone()))?;
            refs.push(latest);
        }
        refs.sort();
        refs.dedup();
        Ok(ToolsetSnapshot::new(refs))
    }

    /// Validates input against the exact snapshotted definition.
    pub fn validate_input(
        &self,
        tool_ref: &ToolRef,
        input: &Value,
    ) -> Result<(), ToolRegistryError> {
        let definition = self.resolve(tool_ref)?;
        let schema = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(definition.input_schema())
            .map_err(|_| ToolRegistryError::CorruptSchema)?;
        if schema.is_valid(input) {
            Ok(())
        } else {
            Err(ToolRegistryError::InputSchemaMismatch)
        }
    }
}
