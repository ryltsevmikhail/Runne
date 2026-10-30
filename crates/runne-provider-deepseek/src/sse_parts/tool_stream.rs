use runne_provider::{
    MAX_PROVIDER_TOOL_ARGUMENT_CONTEXT_BYTES, MAX_PROVIDER_TOOL_CALL_ID_BYTES, ProviderToolNameV1,
};

use crate::DeepSeekResponsesToolProfile;
use runne_provider::ToolProviderProfile;

#[derive(Debug, Default)]
struct ToolStream {
    call_id: String,
    item_id: String,
    name: Option<ProviderToolNameV1>,
    arguments: String,
}

impl DeepSeekSseDecoder {
    /// Creates a decoder that admits only declarations from the opt-in profile.
    #[must_use]
    pub fn for_tool_profile(profile: &DeepSeekResponsesToolProfile) -> Self {
        let mut decoder = Self::default();
        decoder.lifecycle.tools_enabled = true;
        decoder.lifecycle.allowed_tools = profile
            .tool_declarations()
            .iter()
            .map(runne_provider::ProviderToolDeclarationV1::name)
            .collect();
        decoder
    }
}

impl Lifecycle {
    fn accept_tool_added(&mut self, item: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        require_keys(
            item,
            &["arguments", "call_id", "id", "name", "status", "type"],
        )?;
        if self.tool.is_some()
            || required_string(item, "type")? != "function_call"
            || required_string(item, "status")? != "in_progress"
            || !required_string(item, "arguments")?.is_empty()
        {
            return Err(DeepSeekStreamError::UnknownEvent);
        }
        let name = ProviderToolNameV1::from_wire_name(required_string(item, "name")?)
            .ok_or(DeepSeekStreamError::UnknownEvent)?;
        if !self.allowed_tools.contains(&name) {
            return Err(DeepSeekStreamError::UnknownEvent);
        }
        let call_id = required_string(item, "call_id")?;
        if call_id.is_empty()
            || call_id.len() > MAX_PROVIDER_TOOL_CALL_ID_BYTES
            || self.completed_items.iter().any(|v| v["call_id"] == call_id)
        {
            return Err(DeepSeekStreamError::MalformedEvent);
        }
        let item_id = required_string(item, "id")?;
        validate_identifier(item_id)?;
        if self.completed_items.iter().any(|v| v["id"] == item_id) {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        self.tool = Some(ToolStream {
            call_id: call_id.to_owned(),
            item_id: item_id.to_owned(),
            name: Some(name),
            arguments: String::new(),
        });
        self.stage = LifecycleStage::ToolItemAdded;
        Ok(())
    }

    fn accept_tool_delta(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        require_keys(
            event,
            &[
                "delta",
                "item_id",
                "output_index",
                "sequence_number",
                "type",
            ],
        )?;
        if !self.tools_enabled
            || self.stage != LifecycleStage::ToolItemAdded
            || required_u64(event, "output_index")? != self.completed_items.len() as u64
        {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let tool = self
            .tool
            .as_mut()
            .ok_or(DeepSeekStreamError::CorrelationMismatch)?;
        if required_string(event, "item_id")? != tool.item_id {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        let delta = required_string(event, "delta")?;
        let length = tool
            .arguments
            .len()
            .checked_add(delta.len())
            .filter(|size| *size <= MAX_PROVIDER_TOOL_ARGUMENT_CONTEXT_BYTES)
            .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
        tool.arguments.reserve(length - tool.arguments.len());
        tool.arguments.push_str(delta);
        Ok(())
    }

    fn accept_tool_arguments_done(
        &mut self,
        event: &Map<String, Value>,
    ) -> Result<(), DeepSeekStreamError> {
        require_keys(
            event,
            &[
                "arguments",
                "item_id",
                "output_index",
                "sequence_number",
                "type",
            ],
        )?;
        if !self.tools_enabled
            || self.stage != LifecycleStage::ToolItemAdded
            || required_u64(event, "output_index")? != self.completed_items.len() as u64
        {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let tool = self
            .tool
            .as_ref()
            .ok_or(DeepSeekStreamError::CorrelationMismatch)?;
        let args = required_string(event, "arguments")?;
        if required_string(event, "item_id")? != tool.item_id
            || args != tool.arguments
            || args.is_empty()
            || args.len() > MAX_PROVIDER_TOOL_ARGUMENT_CONTEXT_BYTES
            || !serde_json::from_str::<Value>(args).is_ok_and(|value| value.is_object())
        {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        self.stage = LifecycleStage::ToolArgumentsDone;
        Ok(())
    }

    fn accept_tool_item_done(
        &mut self,
        event: &Map<String, Value>,
    ) -> Result<(), DeepSeekStreamError> {
        require_keys(event, &["item", "output_index", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::ToolArgumentsDone
            || required_u64(event, "output_index")? != self.completed_items.len() as u64
        {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let item = required_object(event, "item")?;
        let tool = self
            .tool
            .as_ref()
            .ok_or(DeepSeekStreamError::CorrelationMismatch)?;
        validate_tool_item(item, tool, "completed")?;
        self.push_normalized(ProviderStreamEventKind::ToolCallRequested {
            call_id: tool.call_id.clone(),
            tool_name: tool
                .name
                .ok_or(DeepSeekStreamError::UnknownEvent)?
                .as_str()
                .to_owned(),
            arguments_json: tool.arguments.clone(),
        })?;
        self.completed_items.push(Value::Object(item.clone()));
        self.stage = LifecycleStage::ToolItemDone;
        Ok(())
    }

    fn accept_tool_completed(
        &self,
        response: &Map<String, Value>,
    ) -> Result<(), DeepSeekStreamError> {
        if response.get("output").and_then(Value::as_array) != Some(&self.completed_items) {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        Ok(())
    }
}

fn validate_tool_item(
    item: &Map<String, Value>,
    tool: &ToolStream,
    status: &str,
) -> Result<(), DeepSeekStreamError> {
    require_keys(
        item,
        &["arguments", "call_id", "id", "name", "status", "type"],
    )?;
    let name = tool.name.ok_or(DeepSeekStreamError::UnknownEvent)?;
    if required_string(item, "type")? != "function_call"
        || required_string(item, "status")? != status
        || required_string(item, "id")? != tool.item_id
        || required_string(item, "call_id")? != tool.call_id
        || required_string(item, "name")? != name.wire_name()
        || required_string(item, "arguments")? != tool.arguments
    {
        return Err(DeepSeekStreamError::CorrelationMismatch);
    }
    Ok(())
}
