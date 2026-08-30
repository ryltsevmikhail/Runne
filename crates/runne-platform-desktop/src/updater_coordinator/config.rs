use super::{UpdateCoordinatorError, UpdateTargetBindingConfig};

const MAX_BINDING_VALUE_BYTES: usize = 512;

pub fn validate_binding(binding: &UpdateTargetBindingConfig) -> Result<(), UpdateCoordinatorError> {
    let values = [
        &binding.product_id,
        &binding.platform,
        &binding.arch,
        &binding.min_os,
        &binding.profile_id,
        &binding.bundle_sha256,
        &binding.runtime_version,
        &binding.runtime_digest,
        &binding.channel,
    ];
    if values
        .iter()
        .any(|value| value.is_empty() || value.len() > MAX_BINDING_VALUE_BYTES)
    {
        return Err(UpdateCoordinatorError::InvalidConfiguration);
    }
    Ok(())
}
