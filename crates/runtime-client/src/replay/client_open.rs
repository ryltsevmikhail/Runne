use super::wire::{OpenSessionRequestWire, OpenSessionResponseWire};
use super::{
    AuthenticatedRuntimeClient, CONTENT_TYPE, MAXIMUM_REPLAY_REQUEST_BYTES, ReplayClientError,
    ReplayClientErrorKind, ReplayScope,
};

impl AuthenticatedRuntimeClient {
    pub(super) async fn post_open_session(
        &self,
        body: &OpenSessionRequestWire<'_>,
        scope: ReplayScope,
    ) -> Result<OpenSessionResponseWire, ReplayClientError> {
        let body = serde_json::to_vec(body)
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::InvalidRequest))?;
        if body.len() > MAXIMUM_REPLAY_REQUEST_BYTES {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::InvalidRequest,
            ));
        }
        let response = self
            .authenticated_request(self.http_client().post(self.url("/v1/replay/open-session")))
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::Transport))?;
        super::http::read_open_session_json(response, self.replay_authority(), scope).await
    }
}
