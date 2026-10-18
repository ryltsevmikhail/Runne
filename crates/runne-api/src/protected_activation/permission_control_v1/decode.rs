use super::encode::{MAGIC, VERSION};
use super::validation::MAX_TEXT_BYTES;
use super::{
    PermissionControlContextV1 as Context, PermissionControlDirectionV1 as Direction,
    PermissionControlErrorV1 as Error, PermissionControlManagedChallengeV1 as ManagedChallenge,
    PermissionControlManagedConsentV1 as ManagedConsent,
    PermissionControlModeChallengeV1 as ModeChallenge,
    PermissionControlModeConsentV1 as ModeConsent, PermissionControlPayloadV1 as Payload,
    PermissionControlPurposeV1 as Purpose,
};

pub(super) struct Decoded {
    pub purpose: Purpose,
    pub direction: Direction,
    pub sequence: u64,
    pub context: Context,
    pub payload: Payload,
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::MalformedFrame)?;
        let bytes = self.input.get(self.pos..end).ok_or(Error::MalformedFrame)?;
        self.pos = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn text(&mut self) -> Result<String, Error> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > MAX_TEXT_BYTES {
            return Err(Error::MalformedFrame);
        }
        let text = std::str::from_utf8(self.take(len)?).map_err(|_| Error::MalformedFrame)?;
        Ok(text.to_owned())
    }
    fn option_u64(&mut self) -> Result<Option<u64>, Error> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(Error::MalformedFrame),
        }
    }
    fn option_digest(&mut self) -> Result<Option<[u8; 32]>, Error> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.bytes()?)),
            _ => Err(Error::MalformedFrame),
        }
    }
    fn done(&self) -> bool {
        self.pos == self.input.len()
    }
}

pub(super) fn decode_unsigned(input: &[u8]) -> Result<Decoded, Error> {
    let mut r = Reader::new(input);
    if r.take(8)? != MAGIC || r.u8()? != VERSION {
        return Err(Error::MalformedFrame);
    }
    let purpose = match r.u8()? {
        1 => Purpose::ModeControl,
        2 => Purpose::ManagedPolicyControl,
        _ => return Err(Error::MalformedFrame),
    };
    let direction = match r.u8()? {
        1 => Direction::DesktopToDaemon,
        2 => Direction::DaemonToDesktop,
        _ => return Err(Error::MalformedFrame),
    };
    let sequence = r.u64()?;
    let context = decode_context(&mut r)?;
    let payload = decode_payload(&mut r)?;
    if !r.done() {
        return Err(Error::MalformedFrame);
    }
    Ok(Decoded {
        purpose,
        direction,
        sequence,
        context,
        payload,
    })
}

fn decode_context(r: &mut Reader<'_>) -> Result<Context, Error> {
    Ok(Context {
        runtime_authority: r.text()?,
        store_lineage_id: r.bytes()?,
        stable_subject_digest: r.bytes()?,
        protected_launch_authority_id: r.bytes()?,
        desktop_authority_id: r.bytes()?,
        daemon_instance_id: r.bytes()?,
        protected_session_id: r.bytes()?,
        launch_generation: r.u64()?,
        native_key_epoch: r.u64()?,
        command_id: r.bytes()?,
        idempotency_key: r.text()?,
        public_request_digest: r.bytes()?,
        predecessor_transcript_digest: r.bytes()?,
        issued_at_unix_ms: r.u64()?,
        expires_at_unix_ms: r.u64()?,
    })
}

fn mode(r: &mut Reader<'_>) -> Result<super::PermissionModeSelectionV1, Error> {
    match r.u8()? {
        1 => Ok(super::PermissionModeSelectionV1::AskAlways),
        2 => Ok(super::PermissionModeSelectionV1::RiskBased),
        3 => Ok(super::PermissionModeSelectionV1::FullAccess),
        _ => Err(Error::MalformedFrame),
    }
}
fn decision(r: &mut Reader<'_>) -> Result<super::ManagedDecisionV1, Error> {
    match r.u8()? {
        1 => Ok(super::ManagedDecisionV1::Allow),
        2 => Ok(super::ManagedDecisionV1::Ask),
        3 => Ok(super::ManagedDecisionV1::Deny),
        _ => Err(Error::MalformedFrame),
    }
}
fn policy(r: &mut Reader<'_>) -> Result<super::ManagedPolicyV1, Error> {
    Ok(super::ManagedPolicyV1 {
        fs_read: decision(r)?,
        fs_create: decision(r)?,
        fs_write: decision(r)?,
        fs_delete: decision(r)?,
        process_start: decision(r)?,
        network_use: decision(r)?,
    })
}

fn decode_payload(r: &mut Reader<'_>) -> Result<Payload, Error> {
    Ok(match r.u8()? {
        1 => Payload::ModeRequest(super::PermissionControlModeRequestV1),
        2 => Payload::ModeChallenge(decode_mode_challenge(r)?),
        3 => Payload::ModeConsent(decode_mode_consent(r)?),
        4 => Payload::ManagedRequest(super::PermissionControlManagedRequestV1),
        5 => Payload::ManagedChallenge(decode_managed_challenge(r)?),
        6 => Payload::ManagedConsent(decode_managed_consent(r)?),
        7 => Payload::Cancel,
        8 => Payload::Result(decode_result(r)?),
        _ => return Err(Error::MalformedFrame),
    })
}

fn decode_mode_challenge(r: &mut Reader<'_>) -> Result<ModeChallenge, Error> {
    Ok(ModeChallenge {
        principal: r.text()?,
        workspace_id: r.bytes()?,
        workspace_label: r.text()?,
        expected_authorization_revision: r.u64()?,
        requested_mode: mode(r)?,
        preset_version: r.u16()?,
        mode_expires_at_unix_ms: r.option_u64()?,
        managed_policy_revision: r.u64()?,
        managed_policy_digest: r.bytes()?,
        issued_challenge_binding_digest: r.bytes()?,
        ceremony_expires_at_unix_ms: r.u64()?,
        native_warning_version: r.u16()?,
        challenge_id: r.bytes()?,
        nonce: r.bytes()?,
    })
}
fn decode_mode_consent(r: &mut Reader<'_>) -> Result<ModeConsent, Error> {
    let challenge_id = r.bytes()?;
    let public_request_digest = r.bytes()?;
    let issued_challenge_binding_digest = r.bytes()?;
    let native_warning_version = r.u16()?;
    let requested_mode = mode(r)?;
    let confirmed_binding_digest = r.bytes()?;
    let warning_attestation = r.bytes()?;
    let os_attestation = match r.u8()? {
        0 => super::ModeOsAttestationV1::NotRequired,
        1 => super::ModeOsAttestationV1::Fresh {
            qualified_fingerprint: r.bytes()?,
            authenticated_at_unix_ms: r.u64()?,
        },
        _ => return Err(Error::MalformedFrame),
    };
    Ok(ModeConsent {
        challenge_id,
        public_request_digest,
        issued_challenge_binding_digest,
        native_warning_version,
        requested_mode,
        confirmed_binding_digest,
        warning_attestation,
        os_attestation,
    })
}
fn decode_managed_challenge(r: &mut Reader<'_>) -> Result<ManagedChallenge, Error> {
    Ok(ManagedChallenge {
        registered_administrator_digest: r.bytes()?,
        registration_generation: r.u64()?,
        project_id: r.bytes()?,
        project_label: r.text()?,
        expected_t1_epoch: r.u64()?,
        expected_t1_revision: r.u64()?,
        current_policy: policy(r)?,
        requested_policy: policy(r)?,
        current_policy_digest: r.bytes()?,
        requested_policy_digest: r.bytes()?,
        managed_schema_version: r.u16()?,
        source_schema_version: r.u16()?,
        local_command_schema_version: r.u16()?,
        issued_challenge_binding_digest: r.bytes()?,
        ceremony_expires_at_unix_ms: r.u64()?,
        native_warning_version: r.u16()?,
        challenge_id: r.bytes()?,
        nonce: r.bytes()?,
    })
}
fn decode_managed_consent(r: &mut Reader<'_>) -> Result<ManagedConsent, Error> {
    Ok(ManagedConsent {
        challenge_id: r.bytes()?,
        public_request_digest: r.bytes()?,
        issued_challenge_binding_digest: r.bytes()?,
        native_warning_version: r.u16()?,
        confirmed_binding_digest: r.bytes()?,
        warning_attestation: r.bytes()?,
        qualified_fingerprint: r.bytes()?,
        authenticated_at_unix_ms: r.u64()?,
    })
}
fn decode_result(r: &mut Reader<'_>) -> Result<super::PermissionControlResultV1, Error> {
    let code = match r.u8()? {
        1 => super::PermissionControlResultCodeV1::Pending,
        2 => super::PermissionControlResultCodeV1::Committed,
        3 => super::PermissionControlResultCodeV1::Cancelled,
        4 => super::PermissionControlResultCodeV1::Expired,
        5 => super::PermissionControlResultCodeV1::Invalidated,
        6 => super::PermissionControlResultCodeV1::Denied,
        _ => return Err(Error::MalformedFrame),
    };
    Ok(super::PermissionControlResultV1 {
        code,
        command_id: r.bytes()?,
        public_request_digest: r.bytes()?,
        receipt_digest: r.option_digest()?,
        authorization_revision: r.option_u64()?,
        managed_policy_revision: r.option_u64()?,
    })
}
