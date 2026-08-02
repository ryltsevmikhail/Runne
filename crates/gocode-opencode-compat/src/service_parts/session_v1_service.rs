impl<H: SessionV1HostPort> OpenCodeSessionV1Service<H> {
    pub fn new(host: H, prompt_response_schema: Arc<JSONSchema>) -> Self {
        Self {
            host,
            prompt_response_schema,
        }
    }

    pub async fn prompt(
        &self,
        session_id: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, crate::error::SessionV1Error> {
        let prompt = parse_prompt(session_id, input)?;
        let result = self
            .host
            .prompt(prompt)
            .await
            .map_err(crate::error::SessionV1Error::Host)?;
        if result.session_id != session_id
            || serde_json::to_vec(&result.response)
                .map(|bytes| bytes.len() > MAX_PROMPT_RESPONSE_BYTES)
                .unwrap_or(true)
            || !self.prompt_response_schema.is_valid(&result.response)
            || !valid_prompt_response(session_id, &result.response)
        {
            return Err(crate::error::SessionV1Error::HostOutputMismatch);
        }
        Ok(result.response)
    }

    pub async fn prompt_async(
        &self,
        session_id: &str,
        input: serde_json::Value,
    ) -> Result<(), crate::error::SessionV1Error> {
        let prompt = parse_prompt(session_id, input)?;
        self.host
            .prompt_async(prompt)
            .await
            .map_err(crate::error::SessionV1Error::Host)
    }

    pub async fn status(&self) -> Result<serde_json::Value, crate::error::SessionV1Error> {
        let statuses = self
            .host
            .status()
            .await
            .map_err(crate::error::SessionV1Error::Host)?;
        let mut output = BTreeMap::new();
        for (session_id, status) in statuses {
            validate_session_id(&session_id)?;
            if output.contains_key(&session_id) {
                return Err(crate::error::SessionV1Error::HostOutputMismatch);
            }
            let value = match status {
                CanonicalSessionStatus::Idle => serde_json::json!({"type": "idle"}),
                CanonicalSessionStatus::Busy => serde_json::json!({"type": "busy"}),
                CanonicalSessionStatus::Retry {
                    attempt,
                    message,
                    next,
                } => serde_json::json!({
                    "type": "retry",
                    "attempt": attempt,
                    "message": message,
                    "next": next,
                }),
            };
            output.insert(session_id, value);
        }
        serde_json::to_value(output).map_err(|_| crate::error::SessionV1Error::HostOutputMismatch)
    }

    pub async fn abort(&self, session_id: &str) -> Result<bool, crate::error::SessionV1Error> {
        validate_session_id(session_id)?;
        self.host
            .abort(session_id.to_owned())
            .await
            .map_err(crate::error::SessionV1Error::Host)
    }

}
