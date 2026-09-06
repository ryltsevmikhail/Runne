use crate::error::DaemonError;
use crate::provider_activation::ProviderActivation;

pub async fn compose_selected_provider<T, F, Fut>(
    activation: &ProviderActivation,
    compose: F,
) -> Result<Option<T>, DaemonError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, DaemonError>>,
{
    if activation.requires_openai_execution()
        || activation.requires_deepseek_execution()
        || activation.requires_local_engine_execution()
    {
        compose().await.map(Some)
    } else {
        Ok(None)
    }
}
