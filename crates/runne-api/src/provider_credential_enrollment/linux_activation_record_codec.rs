//! Strict versioned activation record codec. V1 retains its original scope.
use super::{LinuxEnrollmentActivationRecord, LinuxEnrollmentScope, TD1_APPROVAL_MARKER};
use serde::{Deserialize, Serialize};

const V1_SCHEMA: &str = "runne.linux-enrollment-activation.v1";
const V2_SCHEMA: &str = "runne.linux-enrollment-activation.v2";
const CATALOG_APPROVAL: &str = "linux-enrollment-catalog-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDocument {
    schema: String,
    approval: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_scope: Option<String>,
    runtime_root_digest: String,
    desktop_image_digest: String,
    writer_image_digest: String,
    daemon_image_digest: String,
    runtime_authority_id: String,
    machine_id_digest: String,
    approved_at_unix_millis: u64,
}

fn hex64(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex32(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; N];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let high = (chunk[0] as char).to_digit(16)?;
        let low = (chunk[1] as char).to_digit(16)?;
        out[index] = ((high << 4) | low) as u8;
    }
    Some(out)
}

impl LinuxEnrollmentActivationRecord {
    /// Canonical non-secret JSON for the protected config boundary.
    #[must_use]
    pub fn to_config_json(&self) -> String {
        serde_json::to_string(&self.document())
            .unwrap_or_else(|_| unreachable!("plain fields serialize"))
    }

    /// Parses one canonical record document (typed, strict schema).
    #[must_use]
    pub fn from_config_json(json: &str) -> Option<Self> {
        let document = serde_json::from_str::<RecordDocument>(json).ok()?;
        let provider_scope = match (
            document.schema.as_str(),
            document.approval.as_str(),
            document.provider_scope.as_deref(),
        ) {
            (V1_SCHEMA, TD1_APPROVAL_MARKER, None) => LinuxEnrollmentScope::LegacyDeepSeek,
            (V2_SCHEMA, CATALOG_APPROVAL, Some("catalog")) => LinuxEnrollmentScope::Catalog,
            _ => return None,
        };
        Some(Self {
            provider_scope,
            runtime_root_digest: parse_hex(&document.runtime_root_digest)?,
            desktop_image_digest: parse_hex(&document.desktop_image_digest)?,
            writer_image_digest: parse_hex(&document.writer_image_digest)?,
            daemon_image_digest: parse_hex(&document.daemon_image_digest)?,
            runtime_authority_id: parse_hex(&document.runtime_authority_id)?,
            machine_id_digest: parse_hex(&document.machine_id_digest)?,
            approved_at_unix_millis: document.approved_at_unix_millis,
        })
    }

    fn document(&self) -> RecordDocument {
        RecordDocument {
            schema: match self.provider_scope {
                LinuxEnrollmentScope::LegacyDeepSeek => V1_SCHEMA,
                LinuxEnrollmentScope::Catalog => V2_SCHEMA,
            }
            .to_owned(),
            approval: match self.provider_scope {
                LinuxEnrollmentScope::LegacyDeepSeek => TD1_APPROVAL_MARKER,
                LinuxEnrollmentScope::Catalog => CATALOG_APPROVAL,
            }
            .to_owned(),
            provider_scope: match self.provider_scope {
                LinuxEnrollmentScope::LegacyDeepSeek => None,
                LinuxEnrollmentScope::Catalog => Some("catalog".to_owned()),
            },
            runtime_root_digest: hex64(&self.runtime_root_digest),
            desktop_image_digest: hex64(&self.desktop_image_digest),
            writer_image_digest: hex64(&self.writer_image_digest),
            daemon_image_digest: hex64(&self.daemon_image_digest),
            runtime_authority_id: hex32(&self.runtime_authority_id),
            machine_id_digest: hex64(&self.machine_id_digest),
            approved_at_unix_millis: self.approved_at_unix_millis,
        }
    }
}
