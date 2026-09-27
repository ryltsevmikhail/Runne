impl Lifecycle {
    fn accept_item_added(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &["item", "output_index", "sequence_number", "type"],
            DeepSeekDecodeSchemaNode::AddedItem,
        )?;
        if !matches!(
            self.stage,
            LifecycleStage::Created | LifecycleStage::InProgress
        ) || required_u64(event, "output_index")? != 0
        {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let item = traced_required_object(
            &mut self.trace,
            event,
            "item",
            DeepSeekDecodeSchemaNode::AddedItem,
        )?;
        traced_exact_keys(
            &mut self.trace,
            item,
            &["content", "id", "role", "status", "type"],
            DeepSeekDecodeSchemaNode::AddedItem,
        )?;
        validate_added_item(item, &mut self.trace)?;
        let item_id = traced_required_string(
            &mut self.trace,
            item,
            "id",
            DeepSeekDecodeSchemaNode::AddedItem,
        )?;
        validate_identifier(item_id)?;
        self.item_id = Some(item_id.to_owned());
        self.stage = LifecycleStage::ItemAdded;
        Ok(())
    }
}
impl Lifecycle {
    fn accept_part_added(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &[
                "content_index",
                "item_id",
                "output_index",
                "part",
                "sequence_number",
                "type",
            ],
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )?;
        if self.stage != LifecycleStage::ItemAdded {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        let part = traced_required_object(
            &mut self.trace,
            event,
            "part",
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )?;
        traced_exact_keys(
            &mut self.trace,
            part,
            &["annotations", "text", "type"],
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )?;
        validate_part(part, "", true, &mut self.trace)?;
        self.stage = LifecycleStage::PartAdded;
        Ok(())
    }
}
impl Lifecycle {
    fn accept_text_delta(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_subset_keys(
            &mut self.trace,
            event,
            &[
                "content_index",
                "delta",
                "item_id",
                "logprobs",
                "output_index",
                "sequence_number",
                "type",
            ],
            &[
                "content_index",
                "delta",
                "item_id",
                "output_index",
                "sequence_number",
                "type",
            ],
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )?;
        if self.stage != LifecycleStage::PartAdded {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_empty_logprobs(event)?;
        let delta = traced_required_string(
            &mut self.trace,
            event,
            "delta",
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )?;
        if delta.is_empty() {
            self.trace.record(
                DeepSeekDecodePhase::EventSchema,
                DeepSeekDecodeSchemaNode::OutputTextPart,
                DeepSeekDecodeField::Delta,
                DeepSeekDecodeIssue::EmptyTextDelta,
            );
            return Err(DeepSeekStreamError::MalformedEvent);
        }
        let next = self
            .text
            .len()
            .checked_add(delta.len())
            .filter(|length| *length <= DEEPSEEK_MAX_NORMALIZED_TEXT_BYTES)
            .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
        self.text.reserve(next - self.text.len());
        self.text.push_str(delta);
        self.push_normalized(ProviderStreamEventKind::TextDelta {
            text: delta.to_owned(),
        })
    }
}
impl Lifecycle {
    fn accept_text_done(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_subset_keys(
            &mut self.trace,
            event,
            &[
                "content_index",
                "item_id",
                "logprobs",
                "output_index",
                "sequence_number",
                "text",
                "type",
            ],
            &[
                "content_index",
                "item_id",
                "output_index",
                "sequence_number",
                "text",
                "type",
            ],
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )?;
        if self.stage != LifecycleStage::PartAdded {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_empty_logprobs(event)?;
        if traced_required_string(
            &mut self.trace,
            event,
            "text",
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )? != self.text
        {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        self.stage = LifecycleStage::TextDone;
        Ok(())
    }
}
