use gocode_tools::ProcessIntentV1;
use serde_json::Value;

use crate::FixtureMcpFailure;
use crate::discovery::ProcessCallBindingError;

use super::super::{
    FixtureCallCapability, FixturePublication,
    process_call::{ProcessCallMaterial, ProcessDispatchPayload, ProcessEffectKey},
    runtime::FixtureProcessApprovalAuthority,
};

impl FixturePublication {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::fixture) fn issue_process_dispatch_for_test(
        &self,
        tool_name: &str,
        invocation_id: &str,
        input: Value,
        intent: ProcessIntentV1,
        authority: &FixtureProcessApprovalAuthority,
        expires_at: u64,
        issued_at: u64,
    ) -> Result<FixtureCallCapability, FixtureMcpFailure> {
        let prepared = self.prepare_issue(tool_name, invocation_id, &input)?;
        if prepared.tool.execution_class() != crate::McpToolExecutionClass::ProcessBacked {
            return Err(FixtureMcpFailure::ExecutionClassMismatch);
        }
        let capability = self
            .published
            .issue_process_dispatch(
                &self.binding,
                &prepared.tool_ref,
                prepared.invocation.clone(),
                input.clone(),
                &intent,
            )
            .map_err(Self::map_dispatch_error)?;
        capability
            .verify_c2b(&intent)
            .map_err(Self::map_c2b_error)?;
        let request_digest = capability.request_digest();
        let process_capability = authority.issue_capability(&intent, expires_at)?;
        let process_approval = authority.approve(&intent, expires_at, true)?;
        let approval_digest = self.approval_digest(
            &prepared,
            invocation_id,
            request_digest,
            expires_at,
            "fixture-test",
            "fixture-test",
        );
        let key = ProcessEffectKey::new(
            self.issuer_digest,
            self.definition_digest,
            approval_digest,
            invocation_id.to_owned(),
            request_digest,
            self.binding.binding_digest(),
            self.binding.connection_id().to_owned(),
            self.binding.generation(),
            tool_name.to_owned(),
            *intent.digest().as_bytes(),
        );
        Ok(FixtureCallCapability {
            capability: None,
            execution_class: crate::McpToolExecutionClass::ProcessBacked,
            process_key: Some(key),
            process_payload: Some(ProcessDispatchPayload::new(
                capability,
                ProcessCallMaterial::new(intent, process_capability, process_approval, issued_at),
            )),
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
            effect_key: super::super::runtime::EffectKey::new(
                invocation_id.to_owned(),
                request_digest,
                self.binding.binding_digest(),
                self.binding.connection_id().to_owned(),
                self.binding.generation(),
                tool_name.to_owned(),
            ),
        })
    }

    fn approval_digest(
        &self,
        prepared: &super::PreparedIssue<'_>,
        invocation_id: &str,
        request_digest: [u8; 32],
        expires_at: u64,
        principal: &str,
        authority: &str,
    ) -> [u8; 32] {
        super::super::model::digest(&[
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
        ])
    }

    fn map_c2b_error(error: ProcessCallBindingError) -> FixtureMcpFailure {
        match error {
            ProcessCallBindingError::ExecutionClassMismatch => {
                FixtureMcpFailure::ExecutionClassMismatch
            }
            ProcessCallBindingError::ProcessIntentRequired => {
                FixtureMcpFailure::ProcessIntentRequired
            }
            ProcessCallBindingError::ProcessIntentMismatch
            | ProcessCallBindingError::InvalidBinding => {
                FixtureMcpFailure::ProcessCapabilityInvalid
            }
        }
    }
}
