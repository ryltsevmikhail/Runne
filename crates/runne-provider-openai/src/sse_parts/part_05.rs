impl OpenAiSseDecoder {
    /// Creates a decoder requiring exact background and non-stored response evidence.
    #[must_use]
    pub fn background() -> Self {
        let mut decoder = Self::default();
        decoder.lifecycle.background = true;
        decoder
    }

    /// Buffers a fragment without parsing subsequent frames ahead of a durable callback.
    ///
    /// # Errors
    ///
    /// Returns an error when the cumulative stream exceeds a profile bound.
    pub fn append_background_fragment(&mut self, bytes: &[u8]) -> Result<(), OpenAiStreamError> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= OPENAI_MAX_DECODED_STREAM_BYTES)
            .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
        self.pending
            .try_reserve(bytes.len())
            .map_err(|_| OpenAiStreamError::StreamLimitExceeded)?;
        self.pending.extend_from_slice(bytes);
        if self.pending.len() > OPENAI_MAX_SSE_FRAME_BYTES && !self.pending.contains(&b'\n') {
            return Err(OpenAiStreamError::StreamLimitExceeded);
        }
        Ok(())
    }

    /// Parses at most one complete SSE frame, leaving later frames buffered.
    ///
    /// # Errors
    ///
    /// Returns an error when a frame violates the event or profile contract.
    pub fn process_background_frame(&mut self) -> Result<bool, OpenAiStreamError> {
        if !self.pending.contains(&b'\n') {
            return Ok(false);
        }
        let mut consumed = 0usize;
        while let Some(position) = self.pending[consumed..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let line_end = consumed
                .checked_add(position)
                .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
            let wire_bytes = position
                .checked_add(1)
                .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
            let mut line = self.pending[consumed..line_end].to_vec();
            consumed = line_end
                .checked_add(1)
                .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let frame_end = line.is_empty();
            self.accept_line(&line, wire_bytes)?;
            if frame_end {
                self.pending.drain(..consumed);
                return Ok(true);
            }
        }
        self.pending.drain(..consumed);
        if self.pending.len() > OPENAI_MAX_SSE_FRAME_BYTES {
            return Err(OpenAiStreamError::StreamLimitExceeded);
        }
        Ok(false)
    }

    /// Returns the exact response ID learned from a validated created event.
    #[must_use]
    pub fn background_response_id(&self) -> Option<&str> {
        self.lifecycle.response_id.as_deref()
    }

    /// Takes only events parsed through the most recent complete frame.
    pub fn take_background_events(&mut self) -> Vec<ProviderStreamEvent> {
        core::mem::take(&mut self.lifecycle.normalized)
    }
}
