use serde_json::Value;

use crate::{FixtureMcpFailure, McpInvocationId};

use super::{FixtureCallCapability, FixturePublication};

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
        drop(state);
        let tool = self
            .tools
            .get(tool_name)
            .ok_or(FixtureMcpFailure::ToolNotAllowed)?;
        super::schema::validate_value(&input, &self.limits)?;
        super::schema::reject_secret_material(&input)?;
        super::schema::validate_instance(tool.input_schema(), &input)?;
        let expected_id = format!("mcp::{}::{tool_name}", self.binding.server_id().as_str());
        let tool_ref = self
            .published
            .snapshot()
            .tool_refs()
            .iter()
            .find(|reference| reference.tool_id().as_str() == expected_id)
            .ok_or(FixtureMcpFailure::ToolNotAllowed)?;
        let invocation = McpInvocationId::new(invocation_id)
            .map_err(|_| FixtureMcpFailure::CapabilityMissing)?;
        let capability = self
            .published
            .issue_dispatch(&self.binding, tool_ref, invocation, input.clone())
            .map_err(|_| FixtureMcpFailure::CapabilityMissing)?;
        let request_digest = capability.request_digest();
        let bytes = serde_json::to_vec(&input)
            .map_err(|_| FixtureMcpFailure::RequestTooLarge)?
            .len();
        let approval_digest = super::model::digest(&[
            b"fixture-approval-v2",
            principal.as_bytes(),
            authority.as_bytes(),
            invocation_id.as_bytes(),
            request_digest.as_slice(),
            tool_ref.tool_id().as_str().as_bytes(),
            tool_ref.version().to_string().as_bytes(),
            &self.definition_digest,
            &self.issuer_digest,
            &tool.definition_digest(),
            self.binding.connection_id().as_bytes(),
            &self.binding.binding_digest(),
            &self.binding.generation().to_be_bytes(),
            active.runtime_id.as_str().as_bytes(),
            active.session_id.as_str().as_bytes(),
            &expires_at.to_be_bytes(),
            format!("{:?}", self.policy).as_bytes(),
        ]);
        Ok(FixtureCallCapability {
            capability: Some(capability),
            invocation_id: invocation_id.to_owned(),
            approval_digest,
            connection_id: self.binding.connection_id().to_owned(),
            generation: self.binding.generation(),
            expires_at,
            bytes,
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
}
