use gocode_tools::{
    HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1, ProcessIntentDigestV1,
    ProcessIntentV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessSessionIdV1,
    ToolDispatchRequest, ToolRef, ToolRegistryError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::McpInvocationId;

use super::{
    McpDispatchBinding, McpDispatchCapabilityError, McpToolDispatchCapability,
    McpToolExecutionClass, PublishedMcpTools, call_digest,
};

const MAX_INPUT_BYTES: usize = 16_384;
const MAX_INPUT_DEPTH: usize = 8;
const MAX_INPUT_ITEMS: usize = 64;
const MAX_INPUT_STRING_BYTES: usize = 1_024;
const PROCESS_IDENTITY_DOMAIN: &[u8] = b"gocode/mcp-process-identity/v1\0";
const FORBIDDEN_TOKENS: &[&str] = &[
    "authorization",
    "credential",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "secret",
    "privatekey",
    "cookie",
    "sessionsecret",
    "environment",
    "env",
    "path",
    "provider",
    "prompt",
    "output",
    "error",
];

impl PublishedMcpTools {
    /// Issues one opaque protocol capability for an exact published tool call.
    pub fn issue_dispatch(
        &self,
        binding: &McpDispatchBinding,
        tool_ref: &ToolRef,
        invocation_id: McpInvocationId,
        input: Value,
    ) -> Result<McpToolDispatchCapability, McpDispatchCapabilityError> {
        self.issue_for_class(
            binding,
            tool_ref,
            invocation_id,
            input,
            McpToolExecutionClass::ProtocolOnly,
            None,
        )
    }

    /// Issues one opaque process capability bound to an exact intent digest.
    ///
    /// Fixture-owned activation wiring is deferred pending separate approval.
    #[cfg(test)]
    pub(crate) fn issue_process_dispatch(
        &self,
        binding: &McpDispatchBinding,
        tool_ref: &ToolRef,
        invocation_id: McpInvocationId,
        input: Value,
        intent: &ProcessIntentV1,
    ) -> Result<McpToolDispatchCapability, McpDispatchCapabilityError> {
        self.issue_for_class(
            binding,
            tool_ref,
            invocation_id,
            input,
            McpToolExecutionClass::ProcessBacked,
            Some(intent.digest()),
        )
    }

    fn issue_for_class(
        &self,
        binding: &McpDispatchBinding,
        tool_ref: &ToolRef,
        invocation_id: McpInvocationId,
        input: Value,
        required_class: McpToolExecutionClass,
        process_intent_digest: Option<ProcessIntentDigestV1>,
    ) -> Result<McpToolDispatchCapability, McpDispatchCapabilityError> {
        if binding.server_id != self.server_id || binding.discovery_digest != self.discovery_digest
        {
            return Err(McpDispatchCapabilityError::InvalidBinding);
        }
        let definition = self
            .resolve(tool_ref)
            .map_err(|_| McpDispatchCapabilityError::ToolNotPublished)?;
        let execution_class = *self
            .execution_classes
            .get(tool_ref)
            .ok_or(McpDispatchCapabilityError::ToolNotPublished)?;
        let mapping = super::publication_mapping(self.kind, execution_class);
        if definition.class() != mapping.class || definition.sandbox_profile() != mapping.sandbox {
            return Err(McpDispatchCapabilityError::ToolNotPublished);
        }
        let server_tool_name = self
            .server_names
            .get(tool_ref)
            .cloned()
            .ok_or(McpDispatchCapabilityError::ToolNotPublished)?;
        if execution_class != required_class {
            return Err(match required_class {
                McpToolExecutionClass::ProtocolOnly => {
                    McpDispatchCapabilityError::ProcessIntentRequired
                }
                McpToolExecutionClass::ProcessBacked => {
                    McpDispatchCapabilityError::ExecutionClassMismatch
                }
            });
        }
        validate_input_bounds(&input)?;
        reject_secret_material(&input)?;
        self.registry
            .validate_input(tool_ref, &input)
            .map_err(McpDispatchCapabilityError::InvalidInput)?;
        let request_digest = call_digest(binding, tool_ref, &invocation_id, &input);
        Ok(McpToolDispatchCapability {
            binding: binding.clone(),
            tool_ref: tool_ref.clone(),
            invocation_id,
            input,
            server_tool_name,
            request_digest,
            execution_class,
            process_intent_digest,
        })
    }
}

impl McpToolDispatchCapability {
    /// Verifies the opaque capability against the exact process call before consumption.
    pub(crate) fn verify_c2b(
        &self,
        intent: &ProcessIntentV1,
    ) -> Result<(), ProcessCallBindingError> {
        if self.execution_class != McpToolExecutionClass::ProcessBacked {
            return Err(ProcessCallBindingError::ExecutionClassMismatch);
        }
        if self.request_digest
            != call_digest(
                &self.binding,
                &self.tool_ref,
                &self.invocation_id,
                &self.input,
            )
        {
            return Err(ProcessCallBindingError::InvalidBinding);
        }
        if self.process_intent_digest.is_none() {
            return Err(ProcessCallBindingError::ProcessIntentRequired);
        }
        if self.process_intent_digest != Some(intent.digest()) {
            return Err(ProcessCallBindingError::ProcessIntentMismatch);
        }
        if derive_process_lifecycle_binding(&self.binding, &self.invocation_id)
            != intent.lifecycle_binding()
        {
            return Err(ProcessCallBindingError::InvalidBinding);
        }
        Ok(())
    }

    /// Consumes the opaque capability into crate-private exact process dispatch parts.
    #[rustfmt::skip]
    pub(crate) fn into_process_parts(self) -> (McpDispatchBinding, McpToolExecutionClass, ToolDispatchRequest, ProcessLifecycleBindingV1, Option<ProcessIntentDigestV1>) {
        let lifecycle = derive_process_lifecycle_binding(&self.binding, &self.invocation_id);
        let (binding, execution_class, request, process_intent_digest) = self.into_parts(); (binding, execution_class, request, lifecycle, process_intent_digest)
    }

    #[cfg(test)]
    pub(crate) fn without_process_intent_digest_for_test(mut self) -> Self {
        self.process_intent_digest = None;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_invocation_id_for_test(mut self, invocation_id: &str) -> Self {
        self.invocation_id = McpInvocationId::new(invocation_id).expect("test invocation is valid");
        self
    }
}

pub(crate) enum ProcessCallBindingError {
    ExecutionClassMismatch,
    ProcessIntentRequired,
    ProcessIntentMismatch,
    InvalidBinding,
}

fn validate_input_bounds(input: &Value) -> Result<(), McpDispatchCapabilityError> {
    if serde_json::to_vec(input).map_or(true, |encoded| encoded.len() > MAX_INPUT_BYTES) {
        return Err(invalid_input());
    }
    validate_value_bounds(input, 0)
}

fn validate_value_bounds(input: &Value, depth: usize) -> Result<(), McpDispatchCapabilityError> {
    if depth > MAX_INPUT_DEPTH {
        return Err(invalid_input());
    }
    match input {
        Value::String(value) if value.len() > MAX_INPUT_STRING_BYTES => Err(invalid_input()),
        Value::Array(items) if items.len() > MAX_INPUT_ITEMS => Err(invalid_input()),
        Value::Array(items) => items
            .iter()
            .try_for_each(|item| validate_value_bounds(item, depth + 1)),
        Value::Object(items) if items.len() > MAX_INPUT_ITEMS => Err(invalid_input()),
        Value::Object(items) => items.iter().try_for_each(|(key, item)| {
            (key.len() <= MAX_INPUT_STRING_BYTES)
                .then_some(())
                .ok_or_else(invalid_input)?;
            validate_value_bounds(item, depth + 1)
        }),
        _ => Ok(()),
    }
}

fn reject_secret_material(input: &Value) -> Result<(), McpDispatchCapabilityError> {
    match input {
        Value::String(value) if forbidden(value) || value.contains('/') || value.contains('\\') => {
            Err(invalid_input())
        }
        Value::Array(items) => items.iter().try_for_each(reject_secret_material),
        Value::Object(items) => items.iter().try_for_each(|(key, value)| {
            (!forbidden(key)).then_some(()).ok_or_else(invalid_input)?;
            reject_secret_material(value)
        }),
        _ => Ok(()),
    }
}

fn forbidden(value: &str) -> bool {
    let normalized: String = value
        .bytes()
        .filter_map(|byte| {
            byte.is_ascii_alphanumeric()
                .then_some((byte as char).to_ascii_lowercase())
        })
        .collect();
    FORBIDDEN_TOKENS
        .iter()
        .any(|token| normalized.contains(token))
}

fn invalid_input() -> McpDispatchCapabilityError {
    McpDispatchCapabilityError::InvalidInput(ToolRegistryError::InputSchemaMismatch)
}

#[cfg(test)]
mod verification_tests;

#[rustfmt::skip]
pub(crate) fn derive_process_lifecycle_binding(binding: &McpDispatchBinding, invocation: &McpInvocationId) -> ProcessLifecycleBindingV1 {
    fn identity(binding: &McpDispatchBinding, invocation: &McpInvocationId, role: &[u8]) -> [u8; 16] {
        let mut hasher = Sha256::new(); hasher.update(PROCESS_IDENTITY_DOMAIN); hasher.update(role); hasher.update(binding.binding_digest()); hasher.update(invocation.as_str().as_bytes());
        let digest: [u8; 32] = hasher.finalize().into(); let mut value = [0; 16]; value.copy_from_slice(&digest[..16]); if value == [0; 16] { value[15] = 1; } value
    }
    fn typed<T, E>(binding: &McpDispatchBinding, invocation: &McpInvocationId, role: &[u8], constructor: fn([u8; 16]) -> Result<T, E>) -> T {
        let mut value = identity(binding, invocation, role); loop { if let Ok(typed) = constructor(value) { return typed; } value[15] = value[15].wrapping_add(1); }
    }
    ProcessLifecycleBindingV1::new(typed(binding, invocation, b"owner", ProcessOwnerIdV1::new), typed(binding, invocation, b"attempt", ProcessAttemptIdV1::new), typed(binding, invocation, b"session", ProcessSessionIdV1::new), typed(binding, invocation, b"generation", ProcessGenerationIdV1::new), typed(binding, invocation, b"tree", HeldProcessTreeHandleV1::new))
}
