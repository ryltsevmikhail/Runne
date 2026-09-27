#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeepSeekDecodePhase {
    SseLine = 0,
    SseFrame = 1,
    EventSchema = 2,
    Terminal = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeepSeekDecodeEventKind {
    ResponseCreated = 0,
    ResponseInProgress = 1,
    OutputItemAdded = 2,
    ContentPartAdded = 3,
    OutputTextDelta = 4,
    OutputTextDone = 5,
    ContentPartDone = 6,
    OutputItemDone = 7,
    ResponseCompleted = 8,
    ResponseFailed = 9,
    ResponseIncomplete = 10,
    Error = 11,
    #[default]
    Unknown = 12,
    ReasoningTextDelta = 13,
    ReasoningTextDone = 14,
    FunctionCallArgumentsDelta = 15,
    FunctionCallArgumentsDone = 16,
    CustomToolCallInputDelta = 17,
    CustomToolCallInputDone = 18,
}

impl DeepSeekDecodeEventKind {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value {
            "response.created" => Self::ResponseCreated,
            "response.in_progress" => Self::ResponseInProgress,
            "response.output_item.added" => Self::OutputItemAdded,
            "response.content_part.added" => Self::ContentPartAdded,
            "response.output_text.delta" => Self::OutputTextDelta,
            "response.output_text.done" => Self::OutputTextDone,
            "response.content_part.done" => Self::ContentPartDone,
            "response.output_item.done" => Self::OutputItemDone,
            "response.completed" => Self::ResponseCompleted,
            "response.failed" => Self::ResponseFailed,
            "response.incomplete" => Self::ResponseIncomplete,
            "error" => Self::Error,
            "response.reasoning_text.delta" => Self::ReasoningTextDelta,
            "response.reasoning_text.done" => Self::ReasoningTextDone,
            "response.function_call_arguments.delta" => Self::FunctionCallArgumentsDelta,
            "response.function_call_arguments.done" => Self::FunctionCallArgumentsDone,
            "response.custom_tool_call_input.delta" => Self::CustomToolCallInputDelta,
            "response.custom_tool_call_input.done" => Self::CustomToolCallInputDone,
            _ => Self::Unknown,
        }
    }
}

#[cfg_attr(not(feature = "qualification-diagnostics"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeepSeekDecodeSchemaNode {
    SseLine = 0,
    SseFrame = 1,
    EventEnvelope = 2,
    Response = 3,
    Usage = 4,
    AddedItem = 5,
    CompletedItem = 6,
    OutputArray = 7,
    OutputTextPart = 8,
    ErrorEnvelope = 9,
    RemoteErrorResponse = 10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeepSeekDecodeField {
    Event = 0,
    Data = 1,
    Type = 2,
    SequenceNumber = 3,
    Response = 4,
    Id = 5,
    Object = 6,
    Model = 7,
    Status = 8,
    Output = 9,
    Item = 10,
    OutputIndex = 11,
    ContentIndex = 12,
    ItemId = 13,
    Part = 14,
    Delta = 15,
    Text = 16,
    Content = 17,
    Role = 18,
    Annotations = 19,
    Usage = 20,
    InputTokens = 21,
    OutputTokens = 22,
    TotalTokens = 23,
    CachedTokens = 24,
    ReasoningTokens = 25,
    Error = 26,
    Code = 27,
    Message = 28,
    Param = 29,
    IncompleteDetails = 30,
    Reason = 31,
    Logprobs = 32,
    Unknown = 33,
    Metadata = 34,
    CreatedAt = 35,
    Reasoning = 36,
    Summary = 37,
    EncryptedContent = 38,
    Store = 39,
    Background = 40,
    Tools = 41,
}

impl DeepSeekDecodeField {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value {
            "event" => Self::Event,
            "data" => Self::Data,
            "type" => Self::Type,
            "sequence_number" => Self::SequenceNumber,
            "response" => Self::Response,
            "id" => Self::Id,
            "object" => Self::Object,
            "model" => Self::Model,
            "status" => Self::Status,
            "output" => Self::Output,
            "item" => Self::Item,
            "output_index" => Self::OutputIndex,
            "content_index" => Self::ContentIndex,
            "item_id" => Self::ItemId,
            "part" => Self::Part,
            "delta" => Self::Delta,
            "text" => Self::Text,
            "content" => Self::Content,
            "role" => Self::Role,
            "annotations" => Self::Annotations,
            "usage" => Self::Usage,
            "input_tokens" => Self::InputTokens,
            "output_tokens" => Self::OutputTokens,
            "total_tokens" => Self::TotalTokens,
            "cached_tokens" => Self::CachedTokens,
            "reasoning_tokens" => Self::ReasoningTokens,
            "error" => Self::Error,
            "code" => Self::Code,
            "message" => Self::Message,
            "param" => Self::Param,
            "incomplete_details" => Self::IncompleteDetails,
            "reason" => Self::Reason,
            "logprobs" => Self::Logprobs,
            "metadata" => Self::Metadata,
            "created_at" => Self::CreatedAt,
            "reasoning" => Self::Reasoning,
            "summary" => Self::Summary,
            "encrypted_content" => Self::EncryptedContent,
            "store" => Self::Store,
            "background" => Self::Background,
            "tools" => Self::Tools,
            _ => Self::Unknown,
        }
    }
}

#[cfg_attr(not(feature = "qualification-diagnostics"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeepSeekDecodeIssue {
    InvalidUtf8 = 0,
    MissingColon = 1,
    UnsupportedSseField = 2,
    DuplicateEventField = 3,
    EmptyEventName = 4,
    MissingEventName = 5,
    MissingData = 6,
    InvalidJson = 7,
    NotObject = 8,
    MissingField = 9,
    WrongType = 10,
    UnexpectedField = 11,
    KeySetMismatch = 12,
    UnsupportedEvent = 13,
    BoundExceeded = 14,
    EmptyTextDelta = 15,
    ValueMismatch = 16,
    ResponseContractRejected = 17,
    TerminalEvidenceMissing = 18,
    UnclassifiedValidationFailure = 19,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeepSeekDecodeDiagnostic {
    pub phase: DeepSeekDecodePhase,
    pub event: DeepSeekDecodeEventKind,
    pub node: DeepSeekDecodeSchemaNode,
    pub field: DeepSeekDecodeField,
    pub issue: DeepSeekDecodeIssue,
}

impl DeepSeekDecodeDiagnostic {
    #[must_use]
    #[cfg(feature = "qualification-diagnostics")]
    pub const fn ordinals(self) -> (u8, u8, u8, u8, u8) {
        (
            self.phase as u8,
            self.event as u8,
            self.node as u8,
            self.field as u8,
            self.issue as u8,
        )
    }
}

#[derive(Debug, Default)]
pub struct DecodeTrace {
    event: DeepSeekDecodeEventKind,
    failure: Option<DeepSeekDecodeDiagnostic>,
}

impl DecodeTrace {
    pub const fn set_event(&mut self, event: DeepSeekDecodeEventKind) {
        self.event = event;
    }

    pub const fn clear_event(&mut self) {
        self.event = DeepSeekDecodeEventKind::Unknown;
    }

    pub const fn record(
        &mut self,
        phase: DeepSeekDecodePhase,
        node: DeepSeekDecodeSchemaNode,
        field: DeepSeekDecodeField,
        issue: DeepSeekDecodeIssue,
    ) {
        if self.failure.is_none() {
            self.failure = Some(DeepSeekDecodeDiagnostic {
                phase,
                event: self.event,
                node,
                field,
                issue,
            });
        }
    }

    pub const fn failure(&self) -> Option<DeepSeekDecodeDiagnostic> {
        self.failure
    }
}
