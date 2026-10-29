impl Lifecycle {
    fn accept(&mut self, event_name: &str, value: &Value) -> Result<(), DeepSeekStreamError> {
        let event_kind = DeepSeekDecodeEventKind::from_wire(event_name);
        self.trace.set_event(event_kind);
        if self.stage == LifecycleStage::Terminal {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let object = value.as_object().ok_or_else(|| {
            self.trace.record(
                DeepSeekDecodePhase::EventSchema,
                DeepSeekDecodeSchemaNode::EventEnvelope,
                DeepSeekDecodeField::Unknown,
                DeepSeekDecodeIssue::NotObject,
            );
            DeepSeekStreamError::MalformedEvent
        })?;
        let event_type = traced_required_string(
            &mut self.trace,
            object,
            "type",
            DeepSeekDecodeSchemaNode::EventEnvelope,
        )?;
        if event_type != event_name {
            self.trace.record(
                DeepSeekDecodePhase::EventSchema,
                DeepSeekDecodeSchemaNode::EventEnvelope,
                DeepSeekDecodeField::Type,
                DeepSeekDecodeIssue::ValueMismatch,
            );
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        let sequence = traced_required_u64(
            &mut self.trace,
            object,
            "sequence_number",
            DeepSeekDecodeSchemaNode::EventEnvelope,
        )?;
        if self
            .last_remote_sequence
            .is_some_and(|last| sequence <= last)
        {
            self.trace.record(
                DeepSeekDecodePhase::EventSchema,
                DeepSeekDecodeSchemaNode::EventEnvelope,
                DeepSeekDecodeField::SequenceNumber,
                DeepSeekDecodeIssue::ValueMismatch,
            );
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        self.last_remote_sequence = Some(sequence);
        let result = match event_type {
            "response.created" => self.accept_created(object),
            "response.in_progress" => self.accept_in_progress(object),
            "response.output_item.added" => self.accept_item_added(object),
            "response.content_part.added" => self.accept_part_added(object),
            "response.output_text.delta" => self.accept_text_delta(object),
            "response.output_text.done" => self.accept_text_done(object),
            "response.content_part.done" => self.accept_part_done(object),
            "response.output_item.done" if self.tool.is_some() => {
                self.accept_tool_item_done(object)
            }
            "response.output_item.done" => self.accept_item_done(object),
            "response.function_call_arguments.delta" if self.tools_enabled => {
                self.accept_tool_delta(object)
            }
            "response.function_call_arguments.done" if self.tools_enabled => {
                self.accept_tool_arguments_done(object)
            }
            "response.completed" => self.accept_completed(object),
            "response.failed" => self.accept_failed(object),
            "response.incomplete" => self.accept_incomplete(object),
            "error" => self.accept_error(object),
            _ => Err(DeepSeekStreamError::UnknownEvent),
        };
        if result.is_err() && self.trace.failure().is_none() {
            let node = match event_kind {
                DeepSeekDecodeEventKind::ResponseCreated
                | DeepSeekDecodeEventKind::ResponseInProgress
                | DeepSeekDecodeEventKind::ResponseCompleted
                | DeepSeekDecodeEventKind::ResponseFailed
                | DeepSeekDecodeEventKind::ResponseIncomplete => DeepSeekDecodeSchemaNode::Response,
                DeepSeekDecodeEventKind::OutputItemAdded => DeepSeekDecodeSchemaNode::AddedItem,
                DeepSeekDecodeEventKind::OutputItemDone => DeepSeekDecodeSchemaNode::CompletedItem,
                DeepSeekDecodeEventKind::Error => DeepSeekDecodeSchemaNode::ErrorEnvelope,
                _ => DeepSeekDecodeSchemaNode::OutputTextPart,
            };
            let issue = DeepSeekDecodeIssue::UnclassifiedValidationFailure;
            self.trace.record(
                DeepSeekDecodePhase::EventSchema,
                node,
                DeepSeekDecodeField::Unknown,
                issue,
            );
        }
        result
    }
}
impl Lifecycle {
    fn accept_created(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &["response", "sequence_number", "type"],
            DeepSeekDecodeSchemaNode::Response,
        )?;
        if self.stage != LifecycleStage::Start {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "in_progress")?;
        require_empty_output(response)?;
        require_null_or_missing(response, "usage")?;
        self.ensure_started()?;
        self.stage = LifecycleStage::Created;
        Ok(())
    }
}
impl Lifecycle {
    fn accept_in_progress(
        &mut self,
        event: &Map<String, Value>,
    ) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &["response", "sequence_number", "type"],
            DeepSeekDecodeSchemaNode::Response,
        )?;
        if self.stage != LifecycleStage::Created {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "in_progress")?;
        require_empty_output(response)?;
        require_null_or_missing(response, "usage")?;
        self.stage = LifecycleStage::InProgress;
        Ok(())
    }
}
