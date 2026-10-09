use super::validation::MAX_FRAME_BYTES;
use super::{
    PermissionControlContextV1 as Context, PermissionControlDirectionV1 as Direction,
    PermissionControlErrorV1 as Error, PermissionControlManagedChallengeV1 as ManagedChallenge,
    PermissionControlManagedConsentV1 as ManagedConsent,
    PermissionControlModeChallengeV1 as ModeChallenge,
    PermissionControlModeConsentV1 as ModeConsent, PermissionControlPayloadV1 as Payload,
    PermissionControlPurposeV1 as Purpose,
};

pub(super) const MAGIC: &[u8; 8] = b"RNPCTRL1";
pub(super) const VERSION: u8 = 1;
const PREFIX_AND_MAC: usize = 4 + 32;

struct Writer(Vec<u8>);
impl Writer {
    fn new() -> Self {
        Self(Vec::with_capacity(512))
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_FRAME_BYTES - PREFIX_AND_MAC)
        {
            return Err(Error::InvalidContract);
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.bytes(&[value])
    }
    fn u16(&mut self, value: u16) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }
    fn text(&mut self, value: &str) -> Result<(), Error> {
        let len = u16::try_from(value.len()).map_err(|_| Error::InvalidContract)?;
        self.u16(len)?;
        self.bytes(value.as_bytes())
    }
    fn option_u64(&mut self, value: Option<u64>) -> Result<(), Error> {
        match value {
            None => self.u8(0),
            Some(v) => {
                self.u8(1)?;
                self.u64(v)
            }
        }
    }
    fn option_digest(&mut self, value: Option<[u8; 32]>) -> Result<(), Error> {
        match value {
            None => self.u8(0),
            Some(v) => {
                self.u8(1)?;
                self.bytes(&v)
            }
        }
    }
}

pub(super) fn encode_unsigned(
    purpose: Purpose,
    direction: Direction,
    sequence: u64,
    context: &Context,
    payload: &Payload,
) -> Result<Vec<u8>, Error> {
    let mut out = Writer::new();
    out.bytes(MAGIC)?;
    out.u8(VERSION)?;
    out.u8(match purpose {
        Purpose::ModeControl => 1,
        Purpose::ManagedPolicyControl => 2,
    })?;
    out.u8(match direction {
        Direction::DesktopToDaemon => 1,
        Direction::DaemonToDesktop => 2,
    })?;
    out.u64(sequence)?;
    encode_context(&mut out, context)?;
    encode_payload(&mut out, payload)?;
    Ok(out.0)
}

fn encode_context(out: &mut Writer, value: &Context) -> Result<(), Error> {
    out.text(&value.runtime_authority)?;
    out.bytes(&value.store_lineage_id)?;
    out.bytes(&value.stable_subject_digest)?;
    out.bytes(&value.protected_launch_authority_id)?;
    out.bytes(&value.desktop_authority_id)?;
    out.bytes(&value.daemon_instance_id)?;
    out.bytes(&value.protected_session_id)?;
    out.u64(value.launch_generation)?;
    out.u64(value.native_key_epoch)?;
    out.bytes(&value.command_id)?;
    out.text(&value.idempotency_key)?;
    out.bytes(&value.public_request_digest)?;
    out.bytes(&value.predecessor_transcript_digest)?;
    out.u64(value.issued_at_unix_ms)?;
    out.u64(value.expires_at_unix_ms)
}

fn encode_payload(out: &mut Writer, value: &Payload) -> Result<(), Error> {
    match value {
        Payload::ModeRequest(_) => out.u8(1),
        Payload::ModeChallenge(v) => {
            out.u8(2)?;
            encode_mode_challenge(out, v)
        }
        Payload::ModeConsent(v) => {
            out.u8(3)?;
            encode_mode_consent(out, v)
        }
        Payload::ManagedRequest(_) => out.u8(4),
        Payload::ManagedChallenge(v) => {
            out.u8(5)?;
            encode_managed_challenge(out, v)
        }
        Payload::ManagedConsent(v) => {
            out.u8(6)?;
            encode_managed_consent(out, v)
        }
        Payload::Cancel => out.u8(7),
        Payload::Result(v) => {
            out.u8(8)?;
            encode_result(out, v)
        }
    }
}

fn mode_tag(value: super::PermissionModeSelectionV1) -> u8 {
    match value {
        super::PermissionModeSelectionV1::AskAlways => 1,
        super::PermissionModeSelectionV1::RiskBased => 2,
        super::PermissionModeSelectionV1::FullAccess => 3,
    }
}
fn policy(out: &mut Writer, value: super::ManagedPolicyV1) -> Result<(), Error> {
    for item in [
        value.fs_read,
        value.fs_create,
        value.fs_write,
        value.fs_delete,
        value.process_start,
        value.network_use,
    ] {
        out.u8(match item {
            super::ManagedDecisionV1::Allow => 1,
            super::ManagedDecisionV1::Ask => 2,
            super::ManagedDecisionV1::Deny => 3,
        })?;
    }
    Ok(())
}
fn encode_mode_challenge(out: &mut Writer, v: &ModeChallenge) -> Result<(), Error> {
    out.text(&v.principal)?;
    out.bytes(&v.workspace_id)?;
    out.text(&v.workspace_label)?;
    out.u64(v.expected_authorization_revision)?;
    out.u8(mode_tag(v.requested_mode))?;
    out.u16(v.preset_version)?;
    out.option_u64(v.mode_expires_at_unix_ms)?;
    out.u64(v.managed_policy_revision)?;
    out.bytes(&v.managed_policy_digest)?;
    out.bytes(&v.issued_challenge_binding_digest)?;
    out.u64(v.ceremony_expires_at_unix_ms)?;
    out.u16(v.native_warning_version)?;
    out.bytes(&v.challenge_id)?;
    out.bytes(&v.nonce)
}
fn encode_mode_consent(out: &mut Writer, v: &ModeConsent) -> Result<(), Error> {
    out.bytes(&v.challenge_id)?;
    out.bytes(&v.public_request_digest)?;
    out.bytes(&v.issued_challenge_binding_digest)?;
    out.u16(v.native_warning_version)?;
    out.u8(mode_tag(v.requested_mode))?;
    out.bytes(&v.confirmed_binding_digest)?;
    out.bytes(&v.warning_attestation)?;
    match &v.os_attestation {
        super::ModeOsAttestationV1::NotRequired => out.u8(0),
        super::ModeOsAttestationV1::Fresh {
            qualified_fingerprint,
            authenticated_at_unix_ms,
        } => {
            out.u8(1)?;
            out.bytes(qualified_fingerprint)?;
            out.u64(*authenticated_at_unix_ms)
        }
    }
}
fn encode_managed_challenge(out: &mut Writer, v: &ManagedChallenge) -> Result<(), Error> {
    out.bytes(&v.registered_administrator_digest)?;
    out.u64(v.registration_generation)?;
    out.bytes(&v.project_id)?;
    out.text(&v.project_label)?;
    out.u64(v.expected_t1_epoch)?;
    out.u64(v.expected_t1_revision)?;
    policy(out, v.current_policy)?;
    policy(out, v.requested_policy)?;
    out.bytes(&v.current_policy_digest)?;
    out.bytes(&v.requested_policy_digest)?;
    out.u16(v.managed_schema_version)?;
    out.u16(v.source_schema_version)?;
    out.u16(v.local_command_schema_version)?;
    out.bytes(&v.issued_challenge_binding_digest)?;
    out.u64(v.ceremony_expires_at_unix_ms)?;
    out.u16(v.native_warning_version)?;
    out.bytes(&v.challenge_id)?;
    out.bytes(&v.nonce)
}
fn encode_managed_consent(out: &mut Writer, v: &ManagedConsent) -> Result<(), Error> {
    out.bytes(&v.challenge_id)?;
    out.bytes(&v.public_request_digest)?;
    out.bytes(&v.issued_challenge_binding_digest)?;
    out.u16(v.native_warning_version)?;
    out.bytes(&v.confirmed_binding_digest)?;
    out.bytes(&v.warning_attestation)?;
    out.bytes(&v.qualified_fingerprint)?;
    out.u64(v.authenticated_at_unix_ms)
}
fn encode_result(out: &mut Writer, v: &super::PermissionControlResultV1) -> Result<(), Error> {
    out.u8(match v.code {
        super::PermissionControlResultCodeV1::Pending => 1,
        super::PermissionControlResultCodeV1::Committed => 2,
        super::PermissionControlResultCodeV1::Cancelled => 3,
        super::PermissionControlResultCodeV1::Expired => 4,
        super::PermissionControlResultCodeV1::Invalidated => 5,
        super::PermissionControlResultCodeV1::Denied => 6,
    })?;
    out.bytes(&v.command_id)?;
    out.bytes(&v.public_request_digest)?;
    out.option_digest(v.receipt_digest)?;
    out.option_u64(v.authorization_revision)?;
    out.option_u64(v.managed_policy_revision)
}
