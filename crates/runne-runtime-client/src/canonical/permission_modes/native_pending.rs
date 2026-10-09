use crate::canonical::{
    AuthenticatedRuntimeClient, CanonicalId, RuntimeApiError, RuntimeApiErrorKind, read_bounded,
};
use runne_api::{
    ApiPrincipalId, PermissionModeNativePendingPageV2, permission_control_stable_subject_digest_v1,
};
use serde::de::DeserializeOwned;

impl AuthenticatedRuntimeClient {
    /// Reads the bounded native-delivery queue for this authenticated session.
    ///
    /// # Errors
    /// Returns a typed transport error or `InvalidResponse` for an incoherent queue page.
    pub async fn permission_mode_native_pending(
        &self,
        after: Option<CanonicalId>,
    ) -> Result<PermissionModeNativePendingPageV2, RuntimeApiError> {
        let path = after.map_or_else(
            || "/v2/permission-mode/native-pending".to_owned(),
            |cursor| format!("/v2/permission-mode/native-pending?after={cursor}"),
        );
        let response = self
            .authenticated_request(self.http_client().get(self.url(&path)))?
            .send()
            .await
            .map_err(|_| unavailable())?;
        if response.status().as_u16() != 200 {
            return Err(match response.status().as_u16() {
                401 => RuntimeApiError::new(RuntimeApiErrorKind::Unauthorized),
                503 => unavailable(),
                _ => invalid_response(),
            });
        }
        let no_store = response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("no-store"));
        if !no_store {
            return Err(invalid_response());
        }
        let bytes = read_bounded(response, 8 * 1024 * 1024).await?;
        let page: PermissionModeNativePendingPageV2 = decode(&bytes)?;
        validate_page(&page, after, self.session_info())?;
        Ok(page)
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, RuntimeApiError> {
    serde_json::from_slice(bytes).map_err(|_| invalid_response())
}

fn validate_page(
    page: &PermissionModeNativePendingPageV2,
    after: Option<CanonicalId>,
    session: &crate::canonical::RuntimeSessionInfo,
) -> Result<(), RuntimeApiError> {
    use runne_api::MAX_NATIVE_PENDING_PAGE_SIZE_V2 as MAX_PAGE;
    if page.pending.len() > MAX_PAGE || (page.pending.is_empty() && page.next_cursor.is_some()) {
        return Err(invalid_response());
    }
    let expected_authority = uuid_bytes(&session.authority_id)?;
    let expected_lineage = uuid_bytes(&session.event_log_lineage_id)?;
    let principal =
        ApiPrincipalId::new(session.principal_id.clone()).map_err(|_| invalid_response())?;
    let expected_subject =
        permission_control_stable_subject_digest_v1(&principal).map_err(|_| invalid_response())?;
    let mut previous = after;
    for item in &page.pending {
        let workspace = CanonicalId::parse(&item.workspace_id)?;
        let command_id = CanonicalId::parse(&item.context.command_id)?;
        if item.principal_id != session.principal_id
            || item.workspace_id != workspace.to_string()
            || item.context.command_id != command_id.to_string()
            || item.context.runtime_authority != hex::encode(expected_authority)
            || item.context.store_lineage_id != expected_lineage
            || item.context.stable_subject_digest != expected_subject
            || item.context.daemon_instance_id != uuid_bytes(&session.daemon_instance_id)?
            || item.context.protected_session_id != uuid_bytes(&session.session_id)?
            || item.context.launch_generation != session.launch_generation
            || item.context.native_key_epoch == 0
            || item.context.predecessor_transcript_digest != [0; 32]
            || item.context.issued_at_unix_ms == 0
            || item.context.expires_at_unix_ms <= item.context.issued_at_unix_ms
            || item.context.expires_at_unix_ms - item.context.issued_at_unix_ms > 120_000
            || item.context.idempotency_key.is_empty()
            || item.context.idempotency_key.len() > 256
            || item.context.idempotency_key.chars().any(char::is_control)
            || previous.is_some_and(|cursor| command_id <= cursor)
            || item.context.control_context().is_err()
        {
            return Err(invalid_response());
        }
        previous = Some(command_id);
    }
    if page.next_cursor.as_deref().is_some_and(|cursor| {
        page.pending
            .last()
            .is_none_or(|item| cursor != item.context.command_id)
    }) {
        return Err(invalid_response());
    }
    Ok(())
}

fn uuid_bytes(value: &str) -> Result<[u8; 16], RuntimeApiError> {
    let id = CanonicalId::parse(value)?;
    let value = uuid::Uuid::parse_str(&id.to_string()).map_err(|_| invalid_response())?;
    Ok(*value.as_bytes())
}

const fn invalid_response() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)
}

const fn unavailable() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)
}
