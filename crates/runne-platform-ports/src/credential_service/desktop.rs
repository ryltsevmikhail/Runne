use super::{
    CredentialServiceCallContext, CredentialServiceDesktopReply, CredentialServiceDesktopRequest,
    CredentialServicePortFuture,
};

/// Desktop-only registration boundary.
///
/// It deliberately has no mutation, metadata-read or material-read method.
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceCallContext, CredentialServiceDesktopPort,
///     CredentialServiceRuntimeRequest,
/// };
/// fn cannot_arm<P: CredentialServiceDesktopPort>(
///     port: &P,
///     request: CredentialServiceRuntimeRequest,
///     context: CredentialServiceCallContext,
/// ) {
///     port.arm_mutation(request, context);
/// }
/// ```
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceCallContext, CredentialServiceDesktopPort,
///     CredentialServiceWriterRequest,
/// };
/// fn cannot_consume<P: CredentialServiceDesktopPort>(
///     port: &P,
///     request: CredentialServiceWriterRequest,
///     context: CredentialServiceCallContext,
/// ) {
///     port.consume_mutation(request, context);
/// }
/// ```
pub trait CredentialServiceDesktopPort: Send + Sync {
    fn challenge(
        &self,
        request: CredentialServiceDesktopRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply>;

    fn register(
        &self,
        request: CredentialServiceDesktopRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply>;
}
