use bytes::Bytes;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use runne_provider::{DispatchError, ProviderStreamEvent};
use runne_provider_native_wire::{AnthropicStreamDecoder, GeminiStreamDecoder, NativeWireProfile};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial,
};
use runne_store::provider::CredentialDispatchBinding;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::NativeAuthDescriptor;

pub async fn materialize(
    materializer: &Arc<dyn ProviderCredentialDispatchMaterializer>,
    binding: &CredentialDispatchBinding,
    digest: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, DispatchError> {
    let (lifecycle, fence) = binding
        .point_of_use_revisions()
        .map_err(|_| DispatchError::MaybeDispatched)?;
    let materializer = Arc::clone(materializer);
    let capability = binding.native_capability().clone();
    tokio::task::spawn_blocking(move || {
        let read = ProviderCredentialDispatchRead::new(&capability, lifecycle, fence, digest)
            .map_err(|_| denied())?;
        materializer
            .materialize_active(read)
            .map(|value: ProviderCredentialMaterial| {
                Zeroizing::new(value.with_bytes(<[u8]>::to_vec))
            })
            .map_err(|_| denied())
    })
    .await
    .map_err(|_| denied())?
}

pub fn auth_headers(
    auth: NativeAuthDescriptor,
    credential: &Zeroizing<Vec<u8>>,
    anthropic_messages: bool,
) -> Result<HeaderMap, DispatchError> {
    let mut headers = HeaderMap::new();
    match auth {
        NativeAuthDescriptor::AnthropicApiKey => {
            headers.insert(HeaderName::from_static("x-api-key"), sensitive(credential)?);
            headers.insert(
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static("2023-06-01"),
            );
        }
        NativeAuthDescriptor::Bearer | NativeAuthDescriptor::VertexBearer => {
            let mut wire = Zeroizing::new(Vec::with_capacity(7 + credential.len()));
            wire.extend_from_slice(b"Bearer ");
            wire.extend_from_slice(credential);
            headers.insert(AUTHORIZATION, sensitive(&wire)?);
            if anthropic_messages {
                headers.insert(
                    HeaderName::from_static("anthropic-version"),
                    HeaderValue::from_static("2023-06-01"),
                );
            }
        }
        NativeAuthDescriptor::GeminiApiKey => {
            headers.insert(
                HeaderName::from_static("x-goog-api-key"),
                sensitive(credential)?,
            );
        }
    }
    Ok(headers)
}

const fn denied() -> DispatchError {
    DispatchError::RejectedBeforeEffect(
        runne_provider::ProviderPreEffectRejection::CredentialAccessDenied,
    )
}

fn sensitive(value: &Zeroizing<Vec<u8>>) -> Result<HeaderValue, DispatchError> {
    let bytes = Bytes::from_owner(HeaderOwner {
        bytes: value.clone(),
    });
    let mut header =
        HeaderValue::from_maybe_shared(bytes).map_err(|_| DispatchError::MaybeDispatched)?;
    header.set_sensitive(true);
    Ok(header)
}

struct HeaderOwner {
    bytes: Zeroizing<Vec<u8>>,
}
impl AsRef<[u8]> for HeaderOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for HeaderOwner {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub fn decode(profile: &NativeWireProfile, body: &[u8]) -> Result<Vec<ProviderStreamEvent>, ()> {
    match profile {
        NativeWireProfile::Anthropic(profile) => {
            let mut decoder = AnthropicStreamDecoder::for_profile(profile);
            decoder.push(body).map_err(|_| ())?;
            decoder.finish().map_err(|_| ())
        }
        NativeWireProfile::Gemini(profile) => {
            let mut decoder = GeminiStreamDecoder::for_profile(profile);
            decoder.push(body).map_err(|_| ())?;
            decoder.finish().map_err(|_| ())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeAuthDescriptor, auth_headers};
    use zeroize::Zeroizing;

    #[test]
    fn anthropic_version_follows_wire_family_not_bearer_shape() {
        let credential = Zeroizing::new(b"secret".to_vec());
        let bearer = auth_headers(NativeAuthDescriptor::Bearer, &credential, true).unwrap();
        assert_eq!(bearer["anthropic-version"], "2023-06-01");
        assert!(bearer["authorization"].is_sensitive());

        let vertex = auth_headers(NativeAuthDescriptor::VertexBearer, &credential, false).unwrap();
        assert!(vertex.get("anthropic-version").is_none());
        assert!(vertex["authorization"].is_sensitive());

        let gemini = auth_headers(NativeAuthDescriptor::GeminiApiKey, &credential, false).unwrap();
        assert!(gemini.get("anthropic-version").is_none());
        assert!(gemini["x-goog-api-key"].is_sensitive());
    }
}
