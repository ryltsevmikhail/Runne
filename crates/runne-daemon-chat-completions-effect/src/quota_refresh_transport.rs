use bytes::{Bytes, BytesMut};
use runne_provider_quota::QuotaAuthHeaderKind;
use std::{future::Future, pin::Pin, time::Duration};
use zeroize::Zeroizing;

const MAX_BODY_BYTES: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded response returned by an explicitly authorized quota read.
pub struct QuotaRefreshResponse {
    /// HTTP status code.
    pub status: u16,
    /// Provider content type, if present.
    pub content_type: Option<String>,
    /// Bounded response body.
    pub body: Vec<u8>,
}

/// Sanitized failure constructing or executing the quota HTTP transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("quota refresh transport unavailable")]
pub struct QuotaRefreshTransportError;

/// Transport seam for an explicit provider quota operation.
pub trait QuotaRefreshTransport: Send + Sync {
    /// Performs one bounded GET with transient sensitive authorization bytes.
    fn get<'a>(
        &'a self,
        endpoint: String,
        auth: QuotaAuthHeaderKind,
        token: Zeroizing<Vec<u8>>,
        timeout: Duration,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<QuotaRefreshResponse, QuotaRefreshTransportError>>
                + Send
                + 'a,
        >,
    >;
}

/// Production HTTPS quota transport with fixed timeout and no redirects.
pub struct ReqwestQuotaRefreshTransport {
    client: reqwest::Client,
}

impl ReqwestQuotaRefreshTransport {
    /// Creates the bounded provider quota client.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error if the TLS client cannot be constructed.
    pub fn new() -> Result<Self, QuotaRefreshTransportError> {
        reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map(|client| Self { client })
            .map_err(|_| QuotaRefreshTransportError)
    }
}

impl QuotaRefreshTransport for ReqwestQuotaRefreshTransport {
    fn get<'a>(
        &'a self,
        endpoint: String,
        auth: QuotaAuthHeaderKind,
        token: Zeroizing<Vec<u8>>,
        timeout: Duration,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<QuotaRefreshResponse, QuotaRefreshTransportError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let bytes = Bytes::from_owner(AuthorizationOwner::new(auth, &token));
            let mut header = reqwest::header::HeaderValue::from_maybe_shared(bytes)
                .map_err(|_| QuotaRefreshTransportError)?;
            header.set_sensitive(true);
            let response = self
                .client
                .get(endpoint)
                .header(reqwest::header::AUTHORIZATION, header)
                .timeout(timeout.min(REQUEST_TIMEOUT))
                .send()
                .await
                .map_err(|_| QuotaRefreshTransportError)?;
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let mut body = BytesMut::new();
            let mut response = response;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| QuotaRefreshTransportError)?
            {
                if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                    return Err(QuotaRefreshTransportError);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(QuotaRefreshResponse {
                status,
                content_type,
                body: body.to_vec(),
            })
        })
    }
}

struct AuthorizationOwner {
    bytes: Zeroizing<Vec<u8>>,
}

impl AuthorizationOwner {
    fn new(auth: QuotaAuthHeaderKind, token: &Zeroizing<Vec<u8>>) -> Self {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            token.len() + usize::from(matches!(auth, QuotaAuthHeaderKind::BearerAuthorization)) * 7,
        ));
        if auth == QuotaAuthHeaderKind::BearerAuthorization {
            bytes.extend_from_slice(b"Bearer ");
        }
        bytes.extend_from_slice(token);
        Self { bytes }
    }
}

impl AsRef<[u8]> for AuthorizationOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for AuthorizationOwner {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}
