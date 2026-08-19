use runne_tools::ToolRef;
use serde_json::Value;
use std::sync::MutexGuard;

use crate::{
    FixtureMcpFailure, McpDispatchCapabilityError, McpInvocationId, McpToolDispatchCapability,
};

use super::{FixtureCallCapability, FixturePublication, runtime::FixtureState};

#[cfg(test)]
mod process_issuance;

struct PreparedIssue<'a> {
    _state_guard: MutexGuard<'a, FixtureState>,
    active: super::FixtureInitialize,
    tool: super::FixtureTool,
    tool_ref: ToolRef,
    invocation: McpInvocationId,
}

impl FixturePublication {
    /// Issues an exact schema-validated, secret-free, expiry-bound capability.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_dispatch(
        &self,
        tool_name: &str,
        invocation_id: &str,
        input: Value,
        principal: &str,
        authority: &str,
        expires_at: u64,
    ) -> Result<FixtureCallCapability, FixtureMcpFailure> {
        let prepared = self.prepare_issue(tool_name, invocation_id, &input)?;
        let capability = self
            .published
            .issue_dispatch(
                &self.binding,
                &prepared.tool_ref,
                prepared.invocation.clone(),
                input.clone(),
            )
            .map_err(Self::map_dispatch_error)?;
        let request_digest = capability.request_digest();
        self.finish_issue(
            prepared,
            tool_name,
            invocation_id,
            request_digest,
            capability,
            expires_at,
            principal,
            authority,
        )
    }

    fn prepare_issue<'a>(
        &'a self,
        tool_name: &str,
        invocation_id: &str,
        input: &Value,
    ) -> Result<PreparedIssue<'a>, FixtureMcpFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        let active = state
            .active
            .clone()
            .ok_or(FixtureMcpFailure::DiscoveryStale)?;
        if active.connection_id.as_str() != self.binding.connection_id()
            || active.generation != self.binding.generation()
        {
            return Err(FixtureMcpFailure::DiscoveryStale);
        }
        let tool = self
            .tools
            .get(tool_name)
            .cloned()
            .ok_or(FixtureMcpFailure::ToolNotAllowed)?;
        super::schema::validate_value(input, &self.limits)?;
        super::schema::reject_secret_material(input)?;
        super::schema::validate_instance(tool.input_schema(), input)?;
        let expected_id = format!("mcp::{}::{tool_name}", self.binding.server_id().as_str());
        let tool_ref = self
            .published
            .snapshot()
            .tool_refs()
            .iter()
            .find(|reference| reference.tool_id().as_str() == expected_id)
            .cloned()
            .ok_or(FixtureMcpFailure::ToolNotAllowed)?;
        let invocation = McpInvocationId::new(invocation_id)
            .map_err(|_| FixtureMcpFailure::CapabilityMissing)?;
        Ok(PreparedIssue {
            _state_guard: state,
            active,
            tool,
            tool_ref,
            invocation,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_issue(
        &self,
        prepared: PreparedIssue<'_>,
        tool_name: &str,
        invocation_id: &str,
        request_digest: [u8; 32],
        capability: McpToolDispatchCapability,
        expires_at: u64,
        principal: &str,
        authority: &str,
    ) -> Result<FixtureCallCapability, FixtureMcpFailure> {
        let approval_digest = super::model::digest(&[
            b"fixture-approval-v2",
            principal.as_bytes(),
            authority.as_bytes(),
            invocation_id.as_bytes(),
            request_digest.as_slice(),
            prepared.tool_ref.tool_id().as_str().as_bytes(),
            prepared.tool_ref.version().to_string().as_bytes(),
            &self.definition_digest,
            &self.issuer_digest,
            &prepared.tool.definition_digest(),
            self.binding.connection_id().as_bytes(),
            &self.binding.binding_digest(),
            &self.binding.generation().to_be_bytes(),
            prepared.active.runtime_id.as_str().as_bytes(),
            prepared.active.session_id.as_str().as_bytes(),
            &expires_at.to_be_bytes(),
            format!("{:?}", self.policy).as_bytes(),
        ]);
        Ok(FixtureCallCapability {
            capability: Some(capability),
            execution_class: self
                .tools
                .get(tool_name)
                .expect("prepared tool exists")
                .execution_class(),
            process_key: None,
            process_payload: None,
            #[cfg(test)]
            process_payload_take_count: 0,
            invocation_id: invocation_id.to_owned(),
            approval_digest,
            connection_id: self.binding.connection_id().to_owned(),
            generation: self.binding.generation(),
            expires_at,
            request_digest,
            issuer_digest: self.issuer_digest,
            definition_digest: self.definition_digest,
            tool_name: tool_name.to_owned(),
            effect_key: super::runtime::EffectKey::new(
                invocation_id.to_owned(),
                request_digest,
                self.binding.binding_digest(),
                self.binding.connection_id().to_owned(),
                self.binding.generation(),
                tool_name.to_owned(),
            ),
        })
    }

    fn map_dispatch_error(error: McpDispatchCapabilityError) -> FixtureMcpFailure {
        match error {
            McpDispatchCapabilityError::ProcessIntentRequired => {
                FixtureMcpFailure::ProcessIntentRequired
            }
            McpDispatchCapabilityError::ExecutionClassMismatch => {
                FixtureMcpFailure::ExecutionClassMismatch
            }
            _ => FixtureMcpFailure::CapabilityMissing,
        }
    }
}
