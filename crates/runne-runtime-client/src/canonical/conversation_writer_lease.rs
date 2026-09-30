// Authenticated client surface for the conversation writer lease (X2 v1).

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TakeControlWriterLeaseAckWire {
    fencing_token: u64,
}

/// Validated acknowledgement: the lease rotated and this is the new token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TakeControlWriterLeaseAck {
    fencing_token: u64,
}

impl TakeControlWriterLeaseAck {
    const fn observed(fencing_token: u64) -> Self {
        Self { fencing_token }
    }

    /// The new fencing token owned by the requesting principal.
    #[must_use]
    pub const fn fencing_token(self) -> u64 {
        self.fencing_token
    }
}

impl TryFrom<TakeControlWriterLeaseAckWire> for TakeControlWriterLeaseAck {
    type Error = RuntimeApiError;

    fn try_from(wire: TakeControlWriterLeaseAckWire) -> Result<Self, Self::Error> {
        if wire.fencing_token == 0 {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(Self::observed(wire.fencing_token))
    }
}

impl AuthenticatedRuntimeClient {
    /// Rotates the conversation writer lease to this session's principal
    /// after the exact expected fencing token matches.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted failure: `Conflict` on token mismatch.
    pub async fn take_control_conversation_writer_lease(
        &self,
        conversation_id: CanonicalId,
        expected_fencing_token: u64,
    ) -> Result<TakeControlWriterLeaseAck, RuntimeApiError> {
        let url = self.url(&format!(
            "/v1/conversations/{conversation_id}/writer-lease/take-control"
        ));
        let body = serde_json::to_vec(&serde_json::json!({
            "expectedFencingToken": expected_fencing_token,
        }))
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        let response = self
            .authenticated_request(self.http_client().post(url))?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let decoded = read_success_json::<TakeControlWriterLeaseAckWire>(response, &[200]).await?;
        TakeControlWriterLeaseAck::try_from(decoded)
    }
}
