use super::profile::ResponsesProfile;
use super::profile_components::ProfileError;
use sha2::{Digest, Sha256};

const MAX_PROFILE_FIELD_BYTES: usize = 512;
const MAX_ALIASES: usize = 16;
const MAX_ALIAS_BYTES: usize = 512;
const MAX_EXTENSION_BYTES: usize = 128 * 1024;

impl ResponsesProfile {
    /// Validates all public profile components before effect construction.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if [
            self.provider_id.as_ref(),
            self.profile_id.as_str(),
            self.model.as_str(),
            self.model_revision.as_str(),
            self.endpoint.as_ref(),
        ]
        .iter()
        .any(|value| !Self::valid_field(value))
            || self.aliases.len() > MAX_ALIASES
            || self
                .deployment
                .as_deref()
                .is_some_and(|value| !Self::valid_field(value))
            || serde_json::to_vec(&self.binding_extension)
                .map_or(true, |bytes| bytes.len() > MAX_EXTENSION_BYTES)
        {
            return Err(ProfileError::InvalidComponent);
        }
        let mut total = 0usize;
        for alias in &self.aliases {
            if !Self::valid_alias(&[], alias) {
                return Err(ProfileError::InvalidComponent);
            }
            total = total
                .checked_add(alias.len())
                .filter(|value| *value <= MAX_ALIASES * MAX_ALIAS_BYTES)
                .ok_or(ProfileError::InvalidComponent)?;
        }
        Ok(())
    }

    pub(crate) fn valid_alias(existing: &[String], alias: &str) -> bool {
        !alias.is_empty()
            && alias.len() <= MAX_ALIAS_BYTES
            && !alias.chars().any(char::is_control)
            && existing.len() < MAX_ALIASES
            && existing
                .iter()
                .map(String::len)
                .fold(0usize, usize::saturating_add)
                .saturating_add(alias.len())
                <= MAX_ALIASES * MAX_ALIAS_BYTES
    }

    fn valid_field(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= MAX_PROFILE_FIELD_BYTES
            && !value.chars().any(char::is_control)
    }

    pub(crate) fn update_field(digest: &mut Sha256, value: &[u8]) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
}
