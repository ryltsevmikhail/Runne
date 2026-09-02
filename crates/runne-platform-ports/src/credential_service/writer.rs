use super::{
    CredentialServiceCallContext, CredentialServicePortFuture, CredentialServiceWriterReply,
    CredentialServiceWriterRequest,
};

/// One-shot writer-only consume boundary.
///
/// It deliberately has no arm or read operation.
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceCallContext, CredentialServiceRuntimeRequest,
///     CredentialServiceWriterPort,
/// };
/// fn cannot_arm<P: CredentialServiceWriterPort>(
///     port: &P,
///     request: CredentialServiceRuntimeRequest,
///     context: CredentialServiceCallContext,
/// ) {
///     port.arm_mutation(request, context);
/// }
/// ```
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceCallContext, CredentialServiceRuntimeRequest,
///     CredentialServiceWriterPort,
/// };
/// fn cannot_read<P: CredentialServiceWriterPort>(
///     port: &P,
///     request: CredentialServiceRuntimeRequest,
///     context: CredentialServiceCallContext,
/// ) {
///     port.read_material(request, context);
/// }
/// ```
pub trait CredentialServiceWriterPort: Send + Sync {
    fn consume_mutation(
        &self,
        request: CredentialServiceWriterRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceWriterReply>;
}
