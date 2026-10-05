#[derive(Clone)]
struct ToolHandoff {
    disposition: ToolHandoffDisposition,
    calls: Arc<Mutex<Vec<RuntimeToolCall>>>,
}

impl ToolCallHandoffPort for ToolHandoff {
    fn dispatch(
        &self,
        call: &RuntimeToolCall,
    ) -> Result<ToolHandoffDisposition, ProviderToolLoopError> {
        self.calls.lock().unwrap().push(call.clone());
        Ok(self.disposition.clone())
    }
}
