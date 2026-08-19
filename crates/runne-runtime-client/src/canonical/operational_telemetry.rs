const OPERATIONAL_TELEMETRY_PATH: &str = "/v1/runtime/operational-telemetry";

impl AuthenticatedRuntimeClient {
    /// Reads the authenticated runtime operational telemetry snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed, redacted transport/API failure.
    pub async fn operational_telemetry(
        &self,
    ) -> Result<runne_api::RuntimeOperationalTelemetrySnapshotV1, RuntimeApiError> {
        if !self
            .session_info()
            .capabilities
            .iter()
            .any(|value| value == runne_api::OPERATIONAL_TELEMETRY_CAPABILITY_V1)
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        let response = self
            .authenticated_request(self.http_client().get(self.url(OPERATIONAL_TELEMETRY_PATH)))?
            .send()
            .await
            .map_err(map_operational_telemetry_transport)?;
        match response.status() {
            reqwest::StatusCode::UNAUTHORIZED => {
                return Err(RuntimeApiError::new(RuntimeApiErrorKind::Unauthorized));
            }
            reqwest::StatusCode::SERVICE_UNAVAILABLE => {
                return Err(RuntimeApiError::new(RuntimeApiErrorKind::Unavailable));
            }
            reqwest::StatusCode::OK => {}
            _ => return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)),
        }
        if has_access_control_header(&response)
            || !has_exact_header(&response, reqwest::header::CONTENT_TYPE, "application/json")
            || !has_exact_header(&response, reqwest::header::CACHE_CONTROL, "no-store")
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        let bytes = read_operational_telemetry_bounded(response).await?;
        parse_operational_telemetry_wire(&bytes, self.session_info().launch_generation)
    }
}

fn has_access_control_header(response: &reqwest::Response) -> bool {
    response
        .headers()
        .keys()
        .any(|name| name.as_str().starts_with("access-control-"))
}

fn has_exact_header(response: &reqwest::Response, name: reqwest::header::HeaderName, expected: &str) -> bool {
    let mut values = response.headers().get_all(name).iter();
    matches!(values.next().and_then(|value| value.to_str().ok()), Some(value) if value == expected)
        && values.next().is_none()
}

async fn read_operational_telemetry_bounded(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, RuntimeApiError> {
    let content_length = parse_content_length(&response)?;
    let maximum = runne_api::MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1;
    if content_length.is_some_and(|length| length > maximum) {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
    }
    let mut body = Vec::with_capacity(maximum);
    while let Some(chunk) = response.chunk().await.map_err(map_transport)? {
        let length = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        if length > maximum {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_content_length(response: &reqwest::Response) -> Result<Option<usize>, RuntimeApiError> {
    let mut values = response.headers().get_all(reqwest::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
    }
    let value = value
        .to_str()
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}

fn parse_operational_telemetry_wire(
    bytes: &[u8],
    expected_generation: u64,
) -> Result<runne_api::RuntimeOperationalTelemetrySnapshotV1, RuntimeApiError> {
    let snapshot = serde_json::from_slice::<runne_api::RuntimeOperationalTelemetrySnapshotV1>(bytes)
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
    if snapshot.launch_generation() != expected_generation {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
    }
    Ok(snapshot)
}

fn map_operational_telemetry_transport(error: reqwest::Error) -> RuntimeApiError {
    if error.is_connect() || error.is_timeout() {
        map_transport(error)
    } else {
        RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)
    }
}
