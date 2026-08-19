//! Canonical aggregate binding for multi-artifact authority outputs.

use std::collections::BTreeMap;

use runne_project_owner_authority::framed_transcript;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::CliError;

use super::AuthorityFiles;

const DOMAIN: &[u8] = b"runne.authority.cli-output-set/1";
const SCHEMA: &str = "runne.authority.cli-output-set/1";

#[derive(Clone, Copy)]
pub(super) struct OutputArtifact<'a> {
    pub(super) role: &'a str,
    pub(super) path: &'a str,
    pub(super) bytes: &'a [u8],
}
pub(super) struct OutputSet {
    pub(super) manifest: Vec<u8>,
    pub(super) digest: [u8; 32],
}

pub(super) fn rotation_set(
    rotation: OutputArtifact<'_>,
    successor: OutputArtifact<'_>,
) -> Result<OutputSet, CliError> {
    if rotation.role != "rotation"
        || successor.role != "successor-trust"
        || !safe(rotation.path)
        || !safe(successor.path)
        || rotation.path == successor.path
    {
        return Err(CliError::AuthorityUnavailable);
    }
    let mut artifacts = [rotation, successor];
    artifacts.sort_by(|a, b| a.role.cmp(b.role));
    let entries = artifacts
        .into_iter()
        .map(|x| {
            let byte_length =
                u64::try_from(x.bytes.len()).map_err(|_| CliError::AuthorityUnavailable)?;
            Ok(Value::Object(
                BTreeMap::from([
                    (
                        "artifact_sha256".into(),
                        Value::String(hex(&Sha256::digest(x.bytes))),
                    ),
                    ("byte_length".into(), Value::Number(byte_length.into())),
                    ("kind".into(), Value::String("repository-relative".into())),
                    ("locator".into(), Value::String(x.path.into())),
                    ("role".into(), Value::String(x.role.into())),
                ])
                .into_iter()
                .collect(),
            ))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let root: BTreeMap<String, Value> = BTreeMap::from([
        ("artifacts".into(), Value::Array(entries)),
        ("schema_version".into(), Value::String(SCHEMA.into())),
    ]);
    let mut manifest = serde_json::to_vec(&root).map_err(|_| CliError::AuthorityUnavailable)?;
    manifest.push(b'\n');
    let digest: [u8; 32] = Sha256::digest(
        framed_transcript(DOMAIN, &manifest).map_err(|_| CliError::AuthorityUnavailable)?,
    )
    .into();
    Ok(OutputSet { manifest, digest })
}

pub(super) fn write_and_verify<F: AuthorityFiles>(
    files: &F,
    rotation: OutputArtifact<'_>,
    successor: OutputArtifact<'_>,
    expected: &OutputSet,
) -> Result<(), CliError> {
    files.create_new_or_exact_repo_public(rotation.path, rotation.bytes)?;
    files.create_new_or_exact_repo_public(successor.path, successor.bytes)?;
    let reread_rotation = files.read_repo_public(rotation.path)?;
    let reread_successor = files.read_repo_public(successor.path)?;
    let reread = rotation_set(
        OutputArtifact {
            role: rotation.role,
            path: rotation.path,
            bytes: &reread_rotation,
        },
        OutputArtifact {
            role: successor.role,
            path: successor.path,
            bytes: &reread_successor,
        },
    )?;
    if reread_rotation != rotation.bytes
        || reread_successor != successor.bytes
        || reread.manifest != expected.manifest
        || reread.digest != expected.digest
    {
        return Err(CliError::AuthorityUnavailable);
    }
    Ok(())
}
fn safe(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', '\0'])
        && path.bytes().all(|b| !b.is_ascii_control())
        && path
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | "..") && part.trim() == part)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(value, "{byte:02x}").expect("writing to String is infallible");
    }
    value
}
