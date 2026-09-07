use super::{
    CredentialServiceCallContext, CredentialServicePortFuture, CredentialServiceQualificationReply,
    CredentialServiceQualificationRequest,
};

/// ```compile_fail
/// use runne_platform_ports::credential_service::CredentialServiceQualificationRequest;
/// use zeroize::Zeroizing;
///
/// let _ = CredentialServiceQualificationRequest::from_zeroizing(Zeroizing::new(vec![1]));
/// ```
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::CredentialServiceQualificationRequest;
/// use zeroize::Zeroizing;
///
/// let _ = CredentialServiceQualificationRequest(Zeroizing::new(vec![1]));
/// ```
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::CredentialServiceQualificationRequest;
///
/// fn cannot_extract_request(request: CredentialServiceQualificationRequest) {
///     let _ = request.with_bytes(|bytes| bytes.len());
///     let _ = request.into_zeroizing();
/// }
/// ```
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::CredentialServiceQualificationReply;
/// use zeroize::Zeroizing;
///
/// let _ = CredentialServiceQualificationReply::from_zeroizing(Zeroizing::new(vec![1]));
/// ```
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::CredentialServiceQualificationReply;
/// use zeroize::Zeroizing;
///
/// let _ = CredentialServiceQualificationReply(Zeroizing::new(vec![1]));
/// ```
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::CredentialServiceQualificationReply;
///
/// fn cannot_extract_reply(reply: CredentialServiceQualificationReply) {
///     let _ = reply.with_bytes(|bytes| bytes.len());
///     let _ = reply.into_zeroizing();
/// }
/// ```
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceQualificationReply, CredentialServiceQualificationRequest,
/// };
///
/// fn needs_clone<T: Clone>() {}
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_clone::<CredentialServiceQualificationRequest>();
/// needs_clone::<CredentialServiceQualificationReply>();
/// needs_debug::<CredentialServiceQualificationRequest>();
/// needs_debug::<CredentialServiceQualificationReply>();
/// ```
///
/// Authenticated qualification-only exchange boundary.
///
/// This preparatory slice intentionally has no production constructor or byte-transfer
/// capability: an authenticated qualification boundary must be added before this operation
/// can dispatch. Replies remain opaque until that boundary verifies the existing runtime MAC.
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceCallContext, CredentialServiceQualificationPort,
///     CredentialServiceQualificationRequest,
/// };
/// fn cannot_consume<P: CredentialServiceQualificationPort>(
///     port: &P,
///     request: CredentialServiceQualificationRequest,
///     context: CredentialServiceCallContext,
/// ) {
///     port.consume_mutation(request, context);
/// }
/// ```
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceCallContext, CredentialServiceQualificationPort,
///     CredentialServiceQualificationRequest,
/// };
/// fn cannot_exchange_raw<P: CredentialServiceQualificationPort>(
///     port: &P,
///     request: CredentialServiceQualificationRequest,
///     context: CredentialServiceCallContext,
/// ) {
///     port.exchange(request, context);
/// }
/// ```
pub trait CredentialServiceQualificationPort: Send + Sync {
    fn qualify(
        &self,
        request: CredentialServiceQualificationRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceQualificationReply>;
}

#[cfg(test)]
mod guard_tests;
