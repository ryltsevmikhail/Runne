use super::{MAX_INPUT_KINDS, RadiusAccounting, RadiusCatalogModel, RadiusCost, RadiusProfile};
use crate::catalog::validation::{
    bounded_string, bounded_u64, reject_credential_keys, reject_unknown_keys,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(super) fn parse_model(value: &Value) -> Result<RadiusCatalogModel, super::RadiusConfigError> {
    let object = value
        .as_object()
        .ok_or(super::RadiusConfigError::InvalidModel)?;
    reject_unknown_keys(
        object,
        &[
            "id",
            "name",
            "reasoning",
            "thinkingLevelMap",
            "input",
            "contextWindow",
            "maxTokens",
            "cost",
        ],
    )?;
    reject_credential_keys(object)?;
    let id = bounded_string(object.get("id"))?;
    let name = bounded_string(object.get("name"))?;
    let reasoning = object
        .get("reasoning")
        .and_then(Value::as_bool)
        .ok_or(super::RadiusConfigError::InvalidModel)?;
    let input = object
        .get("input")
        .and_then(Value::as_array)
        .ok_or(super::RadiusConfigError::InvalidModel)?;
    if input.is_empty() || input.len() > MAX_INPUT_KINDS {
        return Err(super::RadiusConfigError::InvalidModel);
    }
    let input = input
        .iter()
        .map(|value| bounded_string(Some(value)))
        .collect::<Result<Vec<_>, _>>()?;
    let context_window = bounded_u64(object.get("contextWindow"), false)?;
    let max_tokens = u32::try_from(bounded_u64(object.get("maxTokens"), false)?)
        .map_err(|_| super::RadiusConfigError::InvalidModel)?;
    let cost = object
        .get("cost")
        .and_then(Value::as_object)
        .ok_or(super::RadiusConfigError::InvalidModel)?;
    reject_unknown_keys(cost, &["input", "output", "cacheRead", "cacheWrite"])?;
    let number = |key| {
        cost.get(key)
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value >= 0.0)
            .ok_or(super::RadiusConfigError::InvalidModel)
    };
    Ok(RadiusCatalogModel {
        id,
        name,
        reasoning,
        input,
        context_window,
        max_tokens,
        cost: RadiusCost {
            input: number("input")?,
            output: number("output")?,
            cache_read: number("cacheRead")?,
            cache_write: number("cacheWrite")?,
        },
    })
}

pub(super) struct ProfileDigestInput<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub revision: &'a str,
    pub base_url: &'a str,
    pub catalog: [u8; 32],
    pub max_tokens: u32,
    pub context_window: u64,
    pub max_input_tokens: u64,
    pub max_input_bytes: usize,
    pub accounting: RadiusAccounting,
    pub rates: [u64; 4],
}

pub(super) fn profile_digest(input: &ProfileDigestInput<'_>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne/radius-profile/v1\0");
    for value in [
        input.provider,
        input.model,
        input.revision,
        input.base_url,
        "api_key",
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(input.catalog);
    hash.update(input.max_tokens.to_be_bytes());
    hash.update(input.context_window.to_be_bytes());
    hash.update(input.max_input_tokens.to_be_bytes());
    hash.update((input.max_input_bytes as u64).to_be_bytes());
    hash.update([match input.accounting {
        RadiusAccounting::SubscriptionQuota => 0,
        RadiusAccounting::Payg => 1,
    }]);
    for rate in input.rates {
        hash.update(rate.to_be_bytes());
    }
    hash.finalize().into()
}

impl RadiusProfile {
    /// Returns the selected provider identity.
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    /// Returns the selected dynamic model id.
    pub fn model_id(&self) -> &str {
        &self.model_id
    }
    /// Returns the selected model revision.
    pub fn revision(&self) -> &str {
        &self.revision
    }
    /// Returns the exact validated gateway base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    /// Returns the exact catalog snapshot digest.
    pub const fn catalog_digest(&self) -> [u8; 32] {
        self.catalog_digest
    }
    /// Returns the exact selected-model profile digest.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    /// Returns the catalog-advertised output bound.
    pub const fn max_tokens(&self) -> u32 {
        self.max_tokens
    }
    /// Returns the selected input token cap.
    pub const fn max_input_tokens(&self) -> u64 {
        self.max_input_tokens
    }
    /// Returns the conservative serialized input byte cap.
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }
    /// Returns the bound billing contract.
    pub const fn accounting(&self) -> super::RadiusAccounting {
        self.accounting
    }
}
