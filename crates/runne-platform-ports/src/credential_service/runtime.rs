use super::{
    CredentialServiceCallContext, CredentialServicePortFuture, CredentialServiceRuntimeReply,
    CredentialServiceRuntimeRequest,
};

/// Runtime-only arm and read boundary.
///
/// It deliberately has no writer-consume operation accepting credential
/// material.
///
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceCallContext, CredentialServiceRuntimePort,
///     CredentialServiceWriterRequest,
/// };
/// fn cannot_consume<P: CredentialServiceRuntimePort>(
///     port: &P,
///     request: CredentialServiceWriterRequest,
///     context: CredentialServiceCallContext,
/// ) {
///     port.consume_mutation(request, context);
/// }
/// ```
/// ```compile_fail
/// use runne_platform_ports::credential_service::{
///     CredentialServiceCallContext, CredentialServiceRuntimePort,
/// };
/// use runne_platform_ports::provider_credential_prompt::SecureCredentialMaterial;
/// fn cannot_submit_raw_material<P: CredentialServiceRuntimePort>(
///     port: &P,
///     material: SecureCredentialMaterial,
///     context: CredentialServiceCallContext,
/// ) {
///     port.arm_mutation(material, context);
/// }
/// ```
pub trait CredentialServiceRuntimePort: Send + Sync {
    fn arm_mutation(
        &self,
        request: CredentialServiceRuntimeRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply>;

    fn read_metadata(
        &self,
        request: CredentialServiceRuntimeRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply>;

    fn read_material(
        &self,
        request: CredentialServiceRuntimeRequest,
        context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply>;
}
