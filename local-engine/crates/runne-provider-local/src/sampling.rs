//! Bounded sampling profile (REQ-PROV-122, SAMPLING): the closed
//! `local-engine.sampling.v1` extension map. Two-level validation:
//! size/depth/credential-keys belong to the product ctor; the engine
//! owns domain rules — ranges, unknown fields, the stop budget and the
//! reasoning-effort gate. Out-of-range values REJECT, never clamp
//! (LOCAL-INV-008). The effective map (defaults ∪ override ∩ bounds)
//! canonicalizes into a digest that feeds the attempt identity.

use crate::sampling_error::SamplingError;
use serde_json::{Map, Value};
use sha2::Digest as _;
use std::collections::BTreeMap;

pub const SAMPLING_NAMESPACE: &str = "local-engine.sampling.v1";
/// Whole-profile serialization budget (SAMPLING §LocalSamplingProfileV1).
pub const MAX_PROFILE_BYTES: usize = 1024;
const MAX_STOP_ITEMS: usize = 4;
const MAX_STOP_TOTAL_BYTES: usize = 256;

/// Hard bounds carried by the BackendProfile revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendBounds {
    pub reasoning_supported: bool,
}

impl BackendBounds {
    /// Bounds of the v1 CPU llama.cpp profile.
    pub fn llama_cpu_v1() -> Self {
        Self {
            reasoning_supported: false,
        }
    }
}

/// Immutable default sampling map of the provider profile revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileDefaults {
    pub temperature_milli: u32,
}

impl ProfileDefaults {
    /// v1 default map (SAMPLING §Defaults).
    pub fn v1() -> Self {
        Self {
            temperature_milli: 700,
        }
    }
}

/// Effective, validated sampling map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EffectiveSampling {
    pub temperature_milli: u32,
    pub top_k: Option<u32>,
    pub top_p_milli: Option<u32>,
    pub min_p_milli: Option<u32>,
    pub repeat_penalty_milli: Option<u32>,
    pub stop: Vec<String>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<String>,
}

impl EffectiveSampling {
    /// Canonical digest over the effective map (sorted keys via BTreeMap).
    pub fn digest(&self) -> String {
        let mut m: BTreeMap<String, Value> = BTreeMap::new();
        m.insert(
            "temperature_milli".into(),
            Value::from(self.temperature_milli),
        );
        let opt_u32 = |v: &Option<u32>| -> Value {
            match v {
                Some(x) => Value::from(*x),
                None => Value::Null,
            }
        };
        m.insert("top_k".into(), opt_u32(&self.top_k));
        m.insert("top_p_milli".into(), opt_u32(&self.top_p_milli));
        m.insert("min_p_milli".into(), opt_u32(&self.min_p_milli));
        m.insert(
            "repeat_penalty_milli".into(),
            opt_u32(&self.repeat_penalty_milli),
        );
        m.insert(
            "stop".into(),
            Value::Array(self.stop.iter().cloned().map(Value::String).collect()),
        );
        m.insert(
            "seed".into(),
            match self.seed {
                Some(s) => Value::from(s),
                None => Value::Null,
            },
        );
        m.insert(
            "reasoning_effort".into(),
            match &self.reasoning_effort {
                Some(s) => Value::String(s.clone()),
                None => Value::Null,
            },
        );
        let canonical =
            serde_json_canonicalizer::to_string(&Value::Object(m.into_iter().collect()))
                .unwrap_or_default();
        format!("sha256:{}", hex(&sha256(canonical.as_bytes())))
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, bytes);
    sha2::Digest::finalize(h).into()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Parsed per-call override map (all fields optional).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Override {
    temperature_milli: Option<u32>,
    top_k: Option<u32>,
    top_p_milli: Option<u32>,
    min_p_milli: Option<u32>,
    repeat_penalty_milli: Option<u32>,
    stop: Option<Vec<String>>,
    seed: Option<u64>,
    reasoning_effort: Option<String>,
}

fn get_u32(m: &Map<String, Value>, key: &str) -> Result<Option<u32>, SamplingError> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let v = n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(SamplingError::Malformed)?;
            Ok(Some(v))
        }
        Some(_) => Err(SamplingError::Malformed),
    }
}

fn check_range(name: &'static str, v: Option<u32>, lo: u32, hi: u32) -> Result<(), SamplingError> {
    if let Some(v) = v
        && (v < lo || v > hi)
    {
        return Err(SamplingError::OutOfRange(name));
    }
    Ok(())
}

/// Parses and validates the override map under `namespace` in the
/// call extension, applies profile defaults and backend bounds and
/// returns the effective map. Unknown fields and out-of-range values
/// reject before any host effect.
pub fn effective_sampling(
    extension: &Value,
    defaults: ProfileDefaults,
    bounds: BackendBounds,
) -> Result<EffectiveSampling, SamplingError> {
    let Value::Object(ext) = extension else {
        return Ok(defaults_only(defaults));
    };
    let Some(inner) = ext.get(SAMPLING_NAMESPACE) else {
        return Ok(defaults_only(defaults));
    };
    if serde_json_canonicalizer::to_string(inner)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
        > MAX_PROFILE_BYTES
    {
        return Err(SamplingError::Oversize);
    }
    let Value::Object(m) = inner else {
        return Err(SamplingError::Malformed);
    };
    let known = [
        "temperature_milli",
        "top_k",
        "top_p_milli",
        "min_p_milli",
        "repeat_penalty_milli",
        "stop",
        "seed",
        "reasoning_effort",
    ];
    for k in m.keys() {
        if !known.contains(&k.as_str()) {
            return Err(SamplingError::UnknownField(k.clone()));
        }
    }
    let o = Override {
        temperature_milli: get_u32(m, "temperature_milli")?,
        top_k: get_u32(m, "top_k")?,
        top_p_milli: get_u32(m, "top_p_milli")?,
        min_p_milli: get_u32(m, "min_p_milli")?,
        repeat_penalty_milli: get_u32(m, "repeat_penalty_milli")?,
        stop: match m.get("stop") {
            None | Some(Value::Null) => None,
            Some(Value::Array(a)) => {
                if a.len() > MAX_STOP_ITEMS {
                    return Err(SamplingError::OutOfRange("stop"));
                }
                let mut items = Vec::with_capacity(a.len());
                for item in a {
                    let Value::String(s) = item else {
                        return Err(SamplingError::Malformed);
                    };
                    items.push(s.clone());
                }
                let total: usize = items.iter().map(|s| s.len()).sum();
                if total > MAX_STOP_TOTAL_BYTES {
                    return Err(SamplingError::OutOfRange("stop"));
                }
                Some(items)
            }
            Some(_) => return Err(SamplingError::Malformed),
        },
        seed: match m.get("seed") {
            None | Some(Value::Null) => None,
            Some(Value::Number(n)) => Some(n.as_u64().ok_or(SamplingError::Malformed)?),
            Some(_) => return Err(SamplingError::Malformed),
        },
        reasoning_effort: match m.get("reasoning_effort") {
            None | Some(Value::Null) => None,
            Some(Value::String(s))
                if matches!(s.as_str(), "minimal" | "low" | "medium" | "high") =>
            {
                Some(s.clone())
            }
            Some(_) => return Err(SamplingError::Malformed),
        },
    };
    check_range("temperature_milli", o.temperature_milli, 0, 2000)?;
    check_range("top_k", o.top_k, 0, 1000)?;
    check_range("top_p_milli", o.top_p_milli, 1, 1000)?;
    check_range("min_p_milli", o.min_p_milli, 0, 999)?;
    check_range("repeat_penalty_milli", o.repeat_penalty_milli, 1000, 2000)?;
    if o.reasoning_effort.is_some() && !bounds.reasoning_supported {
        return Err(SamplingError::ReasoningEffortUnsupported);
    }

    Ok(EffectiveSampling {
        temperature_milli: o.temperature_milli.unwrap_or(defaults.temperature_milli),
        top_k: o.top_k,
        top_p_milli: o.top_p_milli,
        min_p_milli: o.min_p_milli,
        repeat_penalty_milli: o.repeat_penalty_milli,
        stop: o.stop.unwrap_or_default(),
        seed: o.seed,
        reasoning_effort: o.reasoning_effort,
    })
}

fn defaults_only(defaults: ProfileDefaults) -> EffectiveSampling {
    EffectiveSampling {
        temperature_milli: defaults.temperature_milli,
        ..Default::default()
    }
}
