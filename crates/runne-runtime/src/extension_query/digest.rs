use super::*;
use sha2::{Digest, Sha256};
const DOMAIN: &[u8] = b"runne/extension-config-metadata/v1\0";
fn string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}
pub(super) fn preimage(
    s: &RegistryScope,
    revision: u64,
    records: &[ConfiguredMetadata],
) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&s.authority_id);
    string(&mut out, s.principal.as_str());
    out.extend_from_slice(s.project.as_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for r in records {
        match r {
            ConfiguredMetadata::Mcp {
                id,
                record_revision,
                transport,
                required_profile,
                ..
            } => {
                out.push(0);
                string(&mut out, &id.0);
                out.extend_from_slice(&record_revision.to_be_bytes());
                out.push(match transport {
                    TransportClass::LocalContained => 0,
                    TransportClass::RemoteBrokered => 1,
                });
                string(&mut out, &required_profile.id.0);
                out.extend_from_slice(&required_profile.revision.to_be_bytes());
            }
            ConfiguredMetadata::Plugin {
                id,
                record_revision,
                package,
                ..
            } => {
                out.push(1);
                string(&mut out, &id.0);
                out.extend_from_slice(&record_revision.to_be_bytes());
                string(&mut out, &package.version.0);
                out.extend_from_slice(&package.digest);
            }
        }
    }
    out
}
pub(super) fn metadata_digest(
    s: &RegistryScope,
    r: u64,
    records: &[ConfiguredMetadata],
) -> [u8; 32] {
    Sha256::digest(preimage(s, r, records)).into()
}
pub(super) fn reply_budget(preimage_len: usize) -> Result<(), MetadataQueryError> {
    match preimage_len.checked_add(16 + 8 + 8 + 32) {
        Some(n) if n <= 131_072 => Ok(()),
        _ => Err(MetadataQueryError::LimitExceeded),
    }
}
pub(super) fn projected_len<'a>(
    s: &RegistryScope,
    records: impl Iterator<Item = &'a ConfiguredMetadata>,
) -> Result<usize, MetadataQueryError> {
    // Domain, schema, authority, length-prefixed principal, project, revision, count.
    let mut len = DOMAIN.len() + 2 + 16 + 4 + s.principal.as_str().len() + 16 + 8 + 4;
    for r in records {
        let n = match r {
            ConfiguredMetadata::Mcp {
                id,
                required_profile,
                ..
            } => 1 + 4 + id.0.len() + 8 + 1 + 4 + required_profile.id.0.len() + 8,
            ConfiguredMetadata::Plugin { id, package, .. } => {
                1 + 4 + id.0.len() + 8 + 4 + package.version.0.len() + 32
            }
        };
        len = len
            .checked_add(n)
            .ok_or(MetadataQueryError::LimitExceeded)?;
    }
    Ok(len)
}
