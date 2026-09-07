//! Bounded GGUF admission parser (first-party safe Rust): header,
//! metadata key/values, tensor infos and aggregate range checks. No
//! process launch, no llama.cpp invocation, no allocation from untrusted
//! counts.

use crate::error::ManifestError;
use crate::gguf_limits::*;
use crate::gguf_metadata::read_metadata_value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct GgufInspection {
    pub version: u32,
    pub kv_count: u64,
    pub tensor_count: u64,
    pub alignment: u64,
    /// Duplicate security-relevant keys already rejected; summary keys
    /// surfaced for the admission decision.
    pub architecture: Option<String>,
    /// Bounded capture of builder-relevant metadata (allowlisted keys
    /// only; everything else is parsed and skipped).
    pub metadata: BTreeMap<String, CapturedValue>,
}

/// Captured metadata value (builder-relevant subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapturedValue {
    Text(String),
    U64(u64),
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    budget: u64,
}

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: u64) -> Result<&'a [u8], ManifestError> {
        let n = usize::try_from(n).map_err(|_| ManifestError::Number("size overflow".into()))?;
        let nu = n as u64;
        if self.budget < nu || (self.bytes.len() as u64) < (self.pos as u64) + nu {
            return Err(ManifestError::Number("gguf: reads exceed bounds".into()));
        }
        self.budget -= nu;
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    pub(crate) fn u32(&mut self) -> Result<u32, ManifestError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| ManifestError::Schema("gguf: bad u32".into()),
        )?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, ManifestError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(
            |_| ManifestError::Schema("gguf: bad u64".into()),
        )?))
    }
    pub(crate) fn string(&mut self) -> Result<String, ManifestError> {
        let len = self.u64()?;
        if len > MAX_STRING_BYTES {
            return Err(ManifestError::Number(format!(
                "gguf string too long: {len}"
            )));
        }
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec()).map_err(|_| ManifestError::InvalidUtf8)
    }
}

/// Parses and bounds-checks a GGUF image fully (metadata + tensor infos +
/// aggregate ranges). Returns the sanitized inspection summary.
pub fn inspect(bytes: &[u8]) -> Result<GgufInspection, ManifestError> {
    if bytes.len() < 24 {
        return Err(ManifestError::Number(
            "gguf: file shorter than header".into(),
        ));
    }
    if bytes[0..4] != GGUF_MAGIC {
        return Err(ManifestError::Schema("gguf: bad magic".into()));
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != GGUF_VERSION {
        return Err(ManifestError::Schema(format!(
            "gguf: unsupported revision {version}"
        )));
    }
    let tensor_count = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    let kv_count = u64::from_le_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
    ]);
    if tensor_count > MAX_TENSOR_COUNT {
        return Err(ManifestError::Number(format!(
            "gguf: tensor count {tensor_count} over limit"
        )));
    }
    if kv_count > MAX_KV_COUNT {
        return Err(ManifestError::Number(format!(
            "gguf: kv count {kv_count} over limit"
        )));
    }
    let metadata_budget = MAX_METADATA_BYTES.min(bytes.len() as u64);
    let mut r = Reader {
        bytes,
        pos: 24,
        budget: metadata_budget,
    };

    let mut seen_keys = BTreeSet::new();
    let mut architecture = None;
    let mut alignment = DEFAULT_ALIGNMENT;
    let mut metadata = BTreeMap::new();
    for i in 0..kv_count {
        let key = r.string()?;
        if !seen_keys.insert(key.clone()) {
            return Err(ManifestError::Schema(format!(
                "gguf: duplicate metadata key {key}"
            )));
        }
        if key == "general.architecture" {
            let ty_raw = r.u32()?;
            if ty_raw != 8 {
                return Err(ManifestError::Schema(
                    "gguf: architecture must be STRING".into(),
                ));
            }
            architecture = Some(r.string()?);
            metadata.insert(
                "general.architecture".into(),
                CapturedValue::Text(architecture.clone().expect("just set")),
            );
            continue;
        }
        if key == "general.alignment" {
            // alignment is U32 per spec; parse explicitly.
            let ty_raw = r.u32()?;
            if ty_raw != 4 {
                return Err(ManifestError::Schema("gguf: alignment must be U32".into()));
            }
            let a = r.u32()? as u64;
            if a == 0 || a > MAX_ALIGNMENT || !a.is_power_of_two() {
                return Err(ManifestError::Schema(format!("gguf: bad alignment {a}")));
            }
            alignment = a;
            continue;
        }
        if let Some(captured) = read_metadata_value(&mut r, 0, &key)? {
            metadata.insert(key, captured);
        }
        let _ = i;
    }

    // Tensor infos: bounded strings/dims, unique names, checked offsets.
    let mut names = BTreeSet::new();
    let mut prev_end: u64 = 0;
    for _ in 0..tensor_count {
        let name = r.string()?;
        if !names.insert(name) {
            return Err(ManifestError::Schema("gguf: duplicate tensor name".into()));
        }
        let n_dims = r.u32()?;
        if n_dims == 0 || n_dims > MAX_TENSOR_DIMS {
            return Err(ManifestError::Number(format!(
                "gguf: bad tensor dim count {n_dims}"
            )));
        }
        let mut elements: u64 = 1;
        for _ in 0..n_dims {
            let d = r.u64()?;
            if d == 0 {
                return Err(ManifestError::Schema("gguf: zero tensor dim".into()));
            }
            elements = elements
                .checked_mul(d)
                .ok_or_else(|| ManifestError::Number("gguf: tensor element overflow".into()))?;
        }
        let ty_id = r.u32()?;
        let Some((bytes_per_block, elems_per_block)) = tensor_type_block(ty_id) else {
            return Err(ManifestError::Schema(format!(
                "gguf: unsupported tensor type {ty_id}"
            )));
        };
        let offset = r.u64()?;
        if offset < prev_end {
            return Err(ManifestError::Schema(
                "gguf: overlapping tensor range".into(),
            ));
        }
        let blocks = elements.div_ceil(elems_per_block);
        let tensor_bytes = blocks
            .checked_mul(bytes_per_block)
            .ok_or_else(|| ManifestError::Number("gguf: tensor size overflow".into()))?;
        let end = offset
            .checked_add(tensor_bytes)
            .ok_or_else(|| ManifestError::Number("gguf: tensor end overflow".into()))?;
        prev_end = end;
    }

    // Tensor data must end exactly at the file end (alignment padding
    // included); trailing structural inconsistency is a rejection.
    let data_start = r.pos as u64;
    let aligned_end = data_start + prev_end.div_ceil(alignment) * alignment;
    if aligned_end != bytes.len() as u64 {
        return Err(ManifestError::Schema(
            "gguf: tensor data does not end at file boundary".into(),
        ));
    }

    Ok(GgufInspection {
        version,
        kv_count,
        tensor_count,
        alignment,
        architecture,
        metadata,
    })
}
