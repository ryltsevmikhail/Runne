use gocode_tools::{ProcessApprovalV1, ProcessCapabilityV1, ProcessIntentV1, ToolDispatchRequest};

use crate::discovery::McpGenerationReadPermit;
use crate::{McpDispatchBinding, McpToolDispatchCapability};

const PROCESS_EFFECT_KEY_DOMAIN: &[u8] = b"GOCODE_MCP_FIXTURE_PROCESS_EFFECT_KEY_V1\0";
const AUDIT_INVOCATION_DOMAIN: &[u8] = b"GOCODE_MCP_FIXTURE_AUDIT_INVOCATION_V1\0";
const AUDIT_CONNECTION_DOMAIN: &[u8] = b"GOCODE_MCP_FIXTURE_AUDIT_CONNECTION_V1\0";
const AUDIT_CAPABILITY_DOMAIN: &[u8] = b"GOCODE_MCP_FIXTURE_AUDIT_CAPABILITY_V1\0";
const PROCESS_PERMIT_DOMAIN: &[u8] = b"GOCODE_MCP_FIXTURE_PROCESS_PERMIT_V1\0";

pub(in crate::fixture) struct ProcessCallMaterial {
    intent: ProcessIntentV1,
    capability: ProcessCapabilityV1,
    approval: ProcessApprovalV1,
    issued_at: u64,
}

pub(in crate::fixture) struct ProcessDispatchPayload {
    capability: McpToolDispatchCapability,
    material: ProcessCallMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::fixture) struct ProcessEffectKey {
    fixture_issuer_digest: [u8; 32],
    fixture_definition_digest: [u8; 32],
    fixture_approval_digest: [u8; 32],
    invocation_id: String,
    request_digest: [u8; 32],
    binding_digest: [u8; 32],
    connection_id: String,
    generation: u64,
    tool_name: String,
    process_intent_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fixture) struct ProcessEffectAuditFields {
    issuer_digest: [u8; 32],
    definition_digest: [u8; 32],
    approval_digest: [u8; 32],
    request_digest: [u8; 32],
    binding_digest: [u8; 32],
    intent_digest: [u8; 32],
    generation: u64,
    tool_digest: [u8; 32],
}

pub(in crate::fixture) struct VerifiedProcessCall {
    request: ToolDispatchRequest,
    binding: McpDispatchBinding,
}

pub(in crate::fixture) struct ClaimedProcessCall<'g> {
    verified: VerifiedProcessCall,
    generation_lease: McpGenerationReadPermit<'g>,
}

impl ProcessCallMaterial {
    #[cfg(test)]
    pub(in crate::fixture) fn new(
        intent: ProcessIntentV1,
        capability: ProcessCapabilityV1,
        approval: ProcessApprovalV1,
        issued_at: u64,
    ) -> Self {
        Self {
            intent,
            capability,
            approval,
            issued_at,
        }
    }

    pub(in crate::fixture) fn intent(&self) -> &ProcessIntentV1 {
        &self.intent
    }
    pub(in crate::fixture) fn capability(&self) -> &ProcessCapabilityV1 {
        &self.capability
    }
    pub(in crate::fixture) fn approval(&self) -> &ProcessApprovalV1 {
        &self.approval
    }
    pub(in crate::fixture) const fn issued_at(&self) -> u64 {
        self.issued_at
    }
}

impl ProcessDispatchPayload {
    #[cfg(test)]
    pub(in crate::fixture) fn new(
        capability: McpToolDispatchCapability,
        material: ProcessCallMaterial,
    ) -> Self {
        Self {
            capability,
            material,
        }
    }

    pub(in crate::fixture) fn mcp(&self) -> &McpToolDispatchCapability {
        &self.capability
    }
    pub(in crate::fixture) fn material(&self) -> &ProcessCallMaterial {
        &self.material
    }
}

impl VerifiedProcessCall {
    pub(in crate::fixture) fn new(
        request: ToolDispatchRequest,
        binding: McpDispatchBinding,
    ) -> Self {
        Self { request, binding }
    }

    pub(in crate::fixture) fn request(&self) -> &ToolDispatchRequest {
        &self.request
    }
    pub(in crate::fixture) fn binding(&self) -> &McpDispatchBinding {
        &self.binding
    }
}

impl<'g> ClaimedProcessCall<'g> {
    pub(in crate::fixture) fn new(
        verified: VerifiedProcessCall,
        generation_lease: McpGenerationReadPermit<'g>,
    ) -> Self {
        Self {
            verified,
            generation_lease,
        }
    }

    pub(in crate::fixture) fn request(&self) -> &ToolDispatchRequest {
        self.verified.request()
    }

    pub(in crate::fixture) fn finish_after_settlement(self) {
        drop(self.generation_lease);
    }
}

impl ProcessEffectKey {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(in crate::fixture) fn new(
        fixture_issuer_digest: [u8; 32],
        fixture_definition_digest: [u8; 32],
        fixture_approval_digest: [u8; 32],
        invocation_id: String,
        request_digest: [u8; 32],
        binding_digest: [u8; 32],
        connection_id: String,
        generation: u64,
        tool_name: String,
        process_intent_digest: [u8; 32],
    ) -> Self {
        Self {
            fixture_issuer_digest,
            fixture_definition_digest,
            fixture_approval_digest,
            invocation_id,
            request_digest,
            binding_digest,
            connection_id,
            generation,
            tool_name,
            process_intent_digest,
        }
    }

    pub(in crate::fixture) fn digest(&self) -> [u8; 32] {
        process_effect_key_digest(self)
    }

    pub(in crate::fixture) fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub(in crate::fixture) fn audit_fields(&self) -> ProcessEffectAuditFields {
        ProcessEffectAuditFields {
            issuer_digest: self.fixture_issuer_digest,
            definition_digest: self.fixture_definition_digest,
            approval_digest: self.fixture_approval_digest,
            request_digest: self.request_digest,
            binding_digest: self.binding_digest,
            intent_digest: self.process_intent_digest,
            generation: self.generation,
            tool_digest: super::model::digest(&[self.tool_name.as_bytes()]),
        }
    }

    pub(in crate::fixture) fn connection_id(&self) -> &str {
        &self.connection_id
    }
}

impl ProcessEffectAuditFields {
    pub(in crate::fixture) fn issuer_digest(&self) -> [u8; 32] {
        self.issuer_digest
    }
    pub(in crate::fixture) fn definition_digest(&self) -> [u8; 32] {
        self.definition_digest
    }
    pub(in crate::fixture) fn approval_digest(&self) -> [u8; 32] {
        self.approval_digest
    }
    pub(in crate::fixture) fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub(in crate::fixture) fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
    pub(in crate::fixture) fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }
    pub(in crate::fixture) const fn generation(&self) -> u64 {
        self.generation
    }
    pub(in crate::fixture) fn tool_digest(&self) -> [u8; 32] {
        self.tool_digest
    }
}

pub(in crate::fixture) fn process_effect_key_digest(key: &ProcessEffectKey) -> [u8; 32] {
    super::model::digest_domain(
        PROCESS_EFFECT_KEY_DOMAIN,
        &[
            &key.fixture_issuer_digest,
            &key.fixture_definition_digest,
            &key.fixture_approval_digest,
            key.invocation_id.as_bytes(),
            &key.request_digest,
            &key.binding_digest,
            key.connection_id.as_bytes(),
            &key.generation.to_be_bytes(),
            key.tool_name.as_bytes(),
            &key.process_intent_digest,
        ],
    )
}

pub(in crate::fixture) fn audit_invocation_digest(invocation_id: &str) -> [u8; 32] {
    super::model::digest_domain(AUDIT_INVOCATION_DOMAIN, &[invocation_id.as_bytes()])
}

pub(in crate::fixture) fn audit_connection_digest(connection_id: &str) -> [u8; 32] {
    super::model::digest_domain(AUDIT_CONNECTION_DOMAIN, &[connection_id.as_bytes()])
}

pub(in crate::fixture) fn audit_capability_digest(capability_id: &[u8]) -> [u8; 32] {
    super::model::digest_domain(AUDIT_CAPABILITY_DOMAIN, &[capability_id])
}

pub(in crate::fixture) fn process_permit_digest(
    effect_key_digest: [u8; 32],
    capability_id: &[u8],
    intent_digest: [u8; 32],
) -> [u8; 32] {
    super::model::digest_domain(
        PROCESS_PERMIT_DOMAIN,
        &[&effect_key_digest, capability_id, &intent_digest],
    )
}

pub(in crate::fixture) fn process_permit_id(digest: [u8; 32]) -> String {
    let mut id = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write;
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    id
}
