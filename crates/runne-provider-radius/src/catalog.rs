use runne_provider::ProviderId;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod pricing;
mod profile;
mod validation;
use validation::{reject_credential_keys, reject_unknown_keys};

/// Default Radius gateway from the pinned Pi provider implementation.
pub const DEFAULT_RADIUS_GATEWAY: &str = "https://radius.pi.dev";
const MAX_CATALOG_BYTES: usize = 1_048_576;
const MAX_MODELS: usize = 4096;
const MAX_INPUT_KINDS: usize = 8;

/// Untrusted monetary metadata carried by the upstream catalog.
#[derive(Debug, Clone, PartialEq)]
pub struct RadiusCost {
    /// Input price metadata, with no Runne currency guarantee.
    pub input: f64,
    /// Output price metadata, with no Runne currency guarantee.
    pub output: f64,
    /// Cache-read price metadata, with no Runne currency guarantee.
    pub cache_read: f64,
    /// Cache-write price metadata, with no Runne currency guarantee.
    pub cache_write: f64,
}

/// One dynamically advertised Radius model.
#[derive(Debug, Clone, PartialEq)]
pub struct RadiusCatalogModel {
    /// Exact gateway model id.
    pub id: String,
    /// Human-readable model name.
    pub name: String,
    /// Whether the gateway advertises reasoning.
    pub reasoning: bool,
    /// Advertised input kinds.
    pub input: Vec<String>,
    /// Advertised context window.
    pub context_window: u64,
    /// Advertised maximum output tokens.
    pub max_tokens: u32,
    /// Untrusted upstream pricing metadata.
    pub cost: RadiusCost,
}

/// Validated dynamic Radius catalog snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct RadiusCatalog {
    base_url: String,
    models: Vec<RadiusCatalogModel>,
    digest: [u8; 32],
}

/// A selected model bound to one exact catalog digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadiusProfile {
    provider_id: String,
    model_id: String,
    revision: String,
    base_url: String,
    catalog_digest: [u8; 32],
    profile_digest: [u8; 32],
    max_tokens: u32,
    max_input_tokens: u64,
    max_input_bytes: usize,
    accounting: RadiusAccounting,
    input_micros_per_million: u64,
    output_micros_per_million: u64,
    cached_input_micros_per_million: u64,
    cache_write_micros_per_million: u64,
}

const RADIUS_PROTOCOL_OVERHEAD_TOKENS: u64 = 256;
const MAX_INPUT_BYTES: usize = 256 * 1024;

/// Explicit Radius billing contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadiusAccounting {
    /// Provider subscription quota; no incremental USD charge.
    SubscriptionQuota,
    /// Owner-explicit PAYG rates from the bound snapshot.
    Payg,
}

/// Dynamic catalog or selection failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RadiusConfigError {
    /// JSON is not a valid object with the pinned catalog shape.
    #[error("Radius catalog is malformed")]
    Malformed,
    /// A gateway URL is not a fixed HTTPS origin/prefix.
    #[error("Radius gateway URL is not a safe HTTPS URL")]
    UnsafeUrl,
    /// A model id was absent or duplicated.
    #[error("Radius catalog model identity is invalid")]
    InvalidModel,
    /// A requested model is not present in the dynamic snapshot.
    #[error("Radius model is not present in the bound catalog")]
    ModelNotFound,
}

impl RadiusCatalog {
    /// Parses and binds one exact `/v1/config` snapshot.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RadiusConfigError> {
        if bytes.is_empty() || bytes.len() > MAX_CATALOG_BYTES {
            return Err(RadiusConfigError::Malformed);
        }
        let root: Value =
            serde_json::from_slice(bytes).map_err(|_| RadiusConfigError::Malformed)?;
        let object = root.as_object().ok_or(RadiusConfigError::Malformed)?;
        reject_unknown_keys(object, &["baseUrl", "models"])?;
        reject_credential_keys(object)?;
        let base_url = object
            .get("baseUrl")
            .and_then(Value::as_str)
            .ok_or(RadiusConfigError::Malformed)?;
        let base_url = normalize_https_url(base_url)?;
        let values = object
            .get("models")
            .and_then(Value::as_array)
            .ok_or(RadiusConfigError::Malformed)?;
        if values.is_empty() || values.len() > MAX_MODELS {
            return Err(RadiusConfigError::Malformed);
        }
        let mut models = Vec::with_capacity(values.len());
        for value in values {
            models.push(profile::parse_model(value)?);
        }
        for (index, model) in models.iter().enumerate() {
            if models[..index].iter().any(|other| other.id == model.id) {
                return Err(RadiusConfigError::InvalidModel);
            }
        }
        Ok(Self {
            base_url,
            models,
            digest: Sha256::digest(bytes).into(),
        })
    }
    /// Parses a snapshot and binds its returned base URL to the trusted gateway.
    pub fn from_json_at(bytes: &[u8], gateway: &str) -> Result<Self, RadiusConfigError> {
        let catalog = Self::from_json(bytes)?;
        if catalog.base_url != normalize_https_url(gateway)? {
            return Err(RadiusConfigError::UnsafeUrl);
        }
        Ok(catalog)
    }
    /// Returns the exact trusted-after-validation gateway base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    /// Returns all dynamically advertised models.
    pub fn models(&self) -> &[RadiusCatalogModel] {
        &self.models
    }
    /// Returns the digest of the exact fetched snapshot bytes.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Selects a model without inventing aliases or static fallback models.
    pub fn select(
        &self,
        provider_id: &str,
        model_id: &str,
        revision: &str,
    ) -> Result<RadiusProfile, RadiusConfigError> {
        self.select_with_accounting(
            provider_id,
            model_id,
            revision,
            RadiusAccounting::SubscriptionQuota,
        )
    }
    /// Selects a model with an explicit billing contract.
    pub fn select_with_accounting(
        &self,
        provider_id: &str,
        model_id: &str,
        revision: &str,
        accounting: RadiusAccounting,
    ) -> Result<RadiusProfile, RadiusConfigError> {
        let model = self
            .models
            .iter()
            .find(|model| model.id == model_id)
            .ok_or(RadiusConfigError::ModelNotFound)?;
        if ProviderId::new(provider_id).is_err() || revision.is_empty() {
            return Err(RadiusConfigError::InvalidModel);
        }
        if model.input != ["text"] {
            return Err(RadiusConfigError::InvalidModel);
        }
        let rates = pricing::rates(&model.cost)?;
        if matches!(accounting, RadiusAccounting::Payg) && (rates[0] == 0 || rates[1] == 0) {
            return Err(RadiusConfigError::InvalidModel);
        }
        let max_input_tokens = model
            .context_window
            .checked_sub(u64::from(model.max_tokens))
            .ok_or(RadiusConfigError::InvalidModel)?;
        let max_input_bytes = usize::try_from(
            max_input_tokens
                .checked_sub(RADIUS_PROTOCOL_OVERHEAD_TOKENS)
                .ok_or(RadiusConfigError::InvalidModel)?,
        )
        .map_err(|_| RadiusConfigError::InvalidModel)?
        .min(MAX_INPUT_BYTES);
        Ok(RadiusProfile {
            provider_id: provider_id.to_owned(),
            model_id: model.id.clone(),
            revision: revision.to_owned(),
            base_url: self.base_url.clone(),
            catalog_digest: self.digest,
            profile_digest: profile::profile_digest(&profile::ProfileDigestInput {
                provider: provider_id,
                model: &model.id,
                revision,
                base_url: &self.base_url,
                catalog: self.digest,
                max_tokens: model.max_tokens,
                context_window: model.context_window,
                max_input_tokens,
                max_input_bytes,
                accounting,
                rates,
            }),
            max_tokens: model.max_tokens,
            max_input_tokens,
            max_input_bytes,
            accounting,
            input_micros_per_million: rates[0],
            output_micros_per_million: rates[1],
            cached_input_micros_per_million: rates[2],
            cache_write_micros_per_million: rates[3],
        })
    }
}

fn normalize_https_url(value: &str) -> Result<String, RadiusConfigError> {
    let url = reqwest_url(value)?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RadiusConfigError::UnsafeUrl);
    }
    let normalized = value.trim_end_matches('/');
    if normalized != DEFAULT_RADIUS_GATEWAY {
        return Err(RadiusConfigError::UnsafeUrl);
    }
    Ok(normalized.to_owned())
}

fn reqwest_url(value: &str) -> Result<reqwest::Url, RadiusConfigError> {
    value.parse().map_err(|_| RadiusConfigError::UnsafeUrl)
}
