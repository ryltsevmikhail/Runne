use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{
    LegacyCleanupEvidence, is_complete_selector_set, is_evidence_digest, is_evidence_run_id_shape,
    scenario_selectors, write_new,
};

const MAX_FRAGMENT_BYTES: u64 = 64 * 1024;

pub(crate) struct LegacyEvidenceBindings {
    candidate_sha256: String,
    tuple_sha256: String,
    workflow_run_id: String,
    final_path: PathBuf,
}

impl LegacyEvidenceBindings {
    pub(crate) fn from_environment() -> Result<Self, &'static str> {
        Self::from_values(
            std::env::var(super::LEGACY_CLEANUP_CANDIDATE_ENV)
                .map_err(|_| "legacy evidence candidate binding is missing")?,
            std::env::var(super::LEGACY_CLEANUP_TUPLE_ENV)
                .map_err(|_| "legacy evidence tuple binding is missing")?,
            std::env::var(super::LEGACY_CLEANUP_RUN_ID_ENV)
                .map_err(|_| "legacy evidence run binding is missing")?,
            PathBuf::from(
                std::env::var_os(super::LEGACY_CLEANUP_EVIDENCE_ENV)
                    .ok_or("legacy evidence output binding is missing")?,
            ),
        )
    }

    pub(crate) fn from_values(
        candidate_sha256: String,
        tuple_sha256: String,
        workflow_run_id: String,
        final_path: PathBuf,
    ) -> Result<Self, &'static str> {
        if !is_evidence_digest(&candidate_sha256) || !is_evidence_digest(&tuple_sha256) {
            return Err("legacy evidence expected digest is invalid");
        }
        if !is_evidence_run_id_shape(&workflow_run_id) {
            return Err("legacy evidence workflow identity is invalid");
        }
        if final_path.as_os_str().is_empty() {
            return Err("legacy evidence output binding is invalid");
        }
        match std::fs::symlink_metadata(&final_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err("legacy evidence output already exists"),
            Err(_) => return Err("legacy evidence output check failed"),
        }
        Ok(Self {
            candidate_sha256,
            tuple_sha256,
            workflow_run_id,
            final_path,
        })
    }

    pub(crate) fn final_path(&self) -> &Path {
        &self.final_path
    }

    pub(crate) fn candidate_sha256(&self) -> &str {
        &self.candidate_sha256
    }

    pub(crate) fn tuple_sha256(&self) -> &str {
        &self.tuple_sha256
    }

    pub(crate) fn workflow_run_id(&self) -> &str {
        &self.workflow_run_id
    }
}

pub(super) fn write_fragment(
    evidence: &LegacyCleanupEvidence,
    path: &Path,
    scenario: &str,
    bindings: &LegacyEvidenceBindings,
) -> Result<(), &'static str> {
    let selectors = scenario_selectors(scenario)?;
    if !is_complete_selector_set(evidence, selectors) {
        return Err("legacy evidence fragment selectors are invalid");
    }
    write_new(
        path,
        canonical_fragment(evidence, scenario, bindings, selectors).as_bytes(),
    )
}

pub(super) fn read_fragment(
    path: &Path,
    scenario: &str,
    bindings: &LegacyEvidenceBindings,
) -> Result<LegacyCleanupEvidence, &'static str> {
    let selectors = scenario_selectors(scenario)?;
    let bytes = read_bounded_regular_file(path)?;
    let source =
        std::str::from_utf8(&bytes).map_err(|_| "legacy evidence fragment format is invalid")?;
    let value: Value =
        serde_json::from_str(source).map_err(|_| "legacy evidence fragment format is invalid")?;
    let object = value
        .as_object()
        .ok_or("legacy evidence fragment format is invalid")?;
    if object.len() != 5
        || string(object.get("candidate_sha256")) != Some(bindings.candidate_sha256.as_str())
        || string(object.get("tuple_sha256")) != Some(bindings.tuple_sha256.as_str())
        || string(object.get("workflow_run_id")) != Some(bindings.workflow_run_id.as_str())
        || string(object.get("scenario")) != Some(scenario)
    {
        return Err("legacy evidence fragment identity is invalid");
    }
    let observed = object
        .get("selectors")
        .and_then(Value::as_object)
        .ok_or("legacy evidence fragment selectors are invalid")?;
    if observed.len() != selectors.len()
        || !selectors.iter().all(|name| observed.contains_key(*name))
    {
        return Err("legacy evidence fragment selectors are invalid");
    }
    let mut evidence = LegacyCleanupEvidence::default();
    for selector in selectors {
        let item = observed
            .get(*selector)
            .and_then(Value::as_object)
            .ok_or("legacy evidence fragment selectors are invalid")?;
        let digest = item
            .get("observation_sha256")
            .and_then(Value::as_str)
            .filter(|value| is_evidence_digest(value))
            .ok_or("legacy evidence fragment selectors are invalid")?;
        if item.len() != 2 || string(item.get("status")) != Some("verified") {
            return Err("legacy evidence fragment selectors are invalid");
        }
        evidence.observations.insert(*selector, digest.to_owned());
    }
    if source != canonical_fragment(&evidence, scenario, bindings, selectors) {
        return Err("legacy evidence fragment format is invalid");
    }
    Ok(evidence)
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, &'static str> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("legacy evidence fragment is missing");
        }
        Ok(metadata) if !metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            return Err("legacy evidence fragment is invalid");
        }
        Err(_) => return Err("legacy evidence fragment is invalid"),
        Ok(_) => {}
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "legacy evidence fragment is invalid")?
        .take(MAX_FRAGMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "legacy evidence fragment is invalid")?;
    if bytes.len() as u64 > MAX_FRAGMENT_BYTES {
        return Err("legacy evidence fragment is too large");
    }
    Ok(bytes)
}

fn canonical_fragment(
    evidence: &LegacyCleanupEvidence,
    scenario: &str,
    bindings: &LegacyEvidenceBindings,
    selectors: &[&str],
) -> String {
    let selectors = selectors
        .iter()
        .map(|selector| {
            let digest = &evidence.observations[*selector];
            format!(
                "\"{selector}\":{{\"observation_sha256\":\"{digest}\",\"status\":\"verified\"}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"candidate_sha256\":\"{}\",\"scenario\":\"{scenario}\",\"selectors\":{{{selectors}}},\"tuple_sha256\":\"{}\",\"workflow_run_id\":\"{}\"}}",
        bindings.candidate_sha256, bindings.tuple_sha256, bindings.workflow_run_id,
    )
}

fn string(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}
