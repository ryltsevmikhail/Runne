#[derive(Debug)]
struct Lifecycle {
    stage: LifecycleStage,
    response_id: Option<String>,
    item_id: Option<String>,
    text: String,
    normalized: Vec<ProviderStreamEvent>,
    last_remote_sequence: Option<u64>,
    trace: DecodeTrace,
    tools_enabled: bool,
    allowed_tools: Vec<ProviderToolNameV1>,
    tool: Option<ToolStream>,
    completed_items: Vec<Value>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            stage: LifecycleStage::Start,
            response_id: None,
            item_id: None,
            text: String::new(),
            normalized: Vec::new(),
            last_remote_sequence: None,
            trace: DecodeTrace::default(),
            tools_enabled: false,
            allowed_tools: Vec::new(),
            tool: None,
            completed_items: Vec::new(),
        }
    }
}
