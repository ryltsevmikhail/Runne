use runne_domain::id::validate_uuid_v7_bytes;

use super::{
    PermissionControlContextV1, PermissionControlErrorV1 as Error,
    PermissionControlManagedChallengeV1, PermissionControlPayloadV1 as Payload,
    PermissionControlPhaseV1 as Phase, PermissionControlPurposeV1 as Purpose,
};

pub(super) const MAX_FRAME_BYTES: usize = 8_192;
pub(super) const MAX_TEXT_BYTES: usize = 256;
pub(super) const MAX_TTL_MS: u64 = 120_000;
pub(super) const WARNING_VERSION_V1: u16 = 1;

pub(super) fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

fn uuid(value: &[u8; 16]) -> bool {
    validate_uuid_v7_bytes(value).is_ok()
}
fn digest(value: &[u8; 32]) -> bool {
    value.iter().any(|byte| *byte != 0)
}
fn finite(value: u64) -> bool {
    value != 0 && value != u64::MAX
}

pub(super) fn validate_context(
    context: &PermissionControlContextV1,
    phase: Phase,
) -> Result<(), Error> {
    let ids = [
        &context.store_lineage_id,
        &context.protected_launch_authority_id,
        &context.desktop_authority_id,
        &context.daemon_instance_id,
        &context.protected_session_id,
        &context.command_id,
    ];
    if !valid_text(&context.runtime_authority)
        || !valid_text(&context.idempotency_key)
        || ids.iter().any(|id| !uuid(id))
        || !digest(&context.stable_subject_digest)
        || !digest(&context.public_request_digest)
        || context.launch_generation == 0
        || context.native_key_epoch == 0
        || !finite(context.issued_at_unix_ms)
        || !finite(context.expires_at_unix_ms)
        || context.expires_at_unix_ms <= context.issued_at_unix_ms
        || context.expires_at_unix_ms - context.issued_at_unix_ms > MAX_TTL_MS
    {
        return Err(Error::InvalidContract);
    }
    let initial = phase == Phase::Request;
    if initial != (context.predecessor_transcript_digest == [0; 32]) {
        return Err(Error::InvalidContract);
    }
    Ok(())
}

pub(super) fn validate_payload(
    purpose: Purpose,
    payload: &Payload,
    context: &PermissionControlContextV1,
) -> Result<(), Error> {
    match payload {
        Payload::ModeRequest(_) if purpose == Purpose::ModeControl => {}
        Payload::ModeChallenge(challenge) if purpose == Purpose::ModeControl => {
            validate_mode_challenge(challenge, context)?;
        }
        Payload::ModeConsent(consent) if purpose == Purpose::ModeControl => {
            if consent.challenge_id == [0; 16]
                || consent.public_request_digest != context.public_request_digest
                || !digest(&consent.issued_challenge_binding_digest)
                || consent.native_warning_version != WARNING_VERSION_V1
                || !digest(&consent.confirmed_binding_digest)
            {
                return Err(Error::InvalidContract);
            }
            match (&consent.requested_mode, &consent.os_attestation) {
                (
                    super::PermissionModeSelectionV1::FullAccess,
                    super::ModeOsAttestationV1::Fresh {
                        authenticated_at_unix_ms,
                        ..
                    },
                ) if fresh_time(*authenticated_at_unix_ms, context) => {}
                (super::PermissionModeSelectionV1::FullAccess, _) => {
                    return Err(Error::InvalidContract);
                }
                (_, super::ModeOsAttestationV1::NotRequired) => {}
                (_, super::ModeOsAttestationV1::Fresh { .. }) => {
                    return Err(Error::InvalidContract);
                }
            }
        }
        Payload::ManagedRequest(_) if purpose == Purpose::ManagedPolicyControl => {}
        Payload::ManagedChallenge(challenge) if purpose == Purpose::ManagedPolicyControl => {
            validate_managed_challenge(challenge, context)?;
        }
        Payload::ManagedConsent(consent) if purpose == Purpose::ManagedPolicyControl => {
            if consent.challenge_id == [0; 16]
                || consent.public_request_digest != context.public_request_digest
                || !digest(&consent.issued_challenge_binding_digest)
                || consent.native_warning_version != WARNING_VERSION_V1
                || !digest(&consent.confirmed_binding_digest)
                || !fresh_time(consent.authenticated_at_unix_ms, context)
            {
                return Err(Error::InvalidContract);
            }
        }
        Payload::Cancel => {}
        Payload::Result(result) => {
            use super::PermissionControlResultCodeV1 as Code;
            if result.command_id != context.command_id
                || result.public_request_digest != context.public_request_digest
            {
                return Err(Error::InvalidContract);
            }
            match result.code {
                Code::Committed
                    if result.receipt_digest.as_ref().is_some_and(digest)
                        && result
                            .authorization_revision
                            .is_some_and(|value| value < u64::MAX)
                        && result
                            .managed_policy_revision
                            .is_some_and(|value| value < u64::MAX) => {}
                Code::Committed => return Err(Error::InvalidContract),
                _ if result.receipt_digest.is_none()
                    && result.authorization_revision.is_none()
                    && result.managed_policy_revision.is_none() => {}
                _ => return Err(Error::InvalidContract),
            }
        }
        _ => return Err(Error::PurposeMismatch),
    }
    Ok(())
}

fn fresh_time(value: u64, context: &PermissionControlContextV1) -> bool {
    finite(value) && value >= context.issued_at_unix_ms && value < context.expires_at_unix_ms
}

fn validate_mode_challenge(
    value: &super::PermissionControlModeChallengeV1,
    context: &PermissionControlContextV1,
) -> Result<(), Error> {
    if !valid_text(&value.principal)
        || !valid_text(&value.workspace_label)
        || !uuid(&value.workspace_id)
        || value.expected_authorization_revision == u64::MAX
        || value.preset_version != 1
        || value.managed_policy_revision == u64::MAX
        || !digest(&value.managed_policy_digest)
        || !digest(&value.issued_challenge_binding_digest)
        || !finite(value.ceremony_expires_at_unix_ms)
        || value.ceremony_expires_at_unix_ms > context.expires_at_unix_ms
        || value.native_warning_version != WARNING_VERSION_V1
        || value.challenge_id == [0; 16]
        || value.nonce == [0; 32]
        || value
            .mode_expires_at_unix_ms
            .is_some_and(|expiry| !finite(expiry) || expiry < context.expires_at_unix_ms)
    {
        return Err(Error::InvalidContract);
    }
    Ok(())
}

fn validate_managed_challenge(
    value: &PermissionControlManagedChallengeV1,
    context: &PermissionControlContextV1,
) -> Result<(), Error> {
    if !digest(&value.registered_administrator_digest)
        || value.registration_generation == 0
        || !uuid(&value.project_id)
        || !valid_text(&value.project_label)
        || value.expected_t1_epoch == 0
        || value.expected_t1_revision == 0
        || !digest(&value.current_policy_digest)
        || !digest(&value.requested_policy_digest)
        || value.managed_schema_version != 1
        || value.source_schema_version != 2
        || value.local_command_schema_version != 1
        || !digest(&value.issued_challenge_binding_digest)
        || !finite(value.ceremony_expires_at_unix_ms)
        || value.ceremony_expires_at_unix_ms > context.expires_at_unix_ms
        || value.native_warning_version != WARNING_VERSION_V1
        || value.challenge_id == [0; 16]
        || value.nonce == [0; 32]
    {
        return Err(Error::InvalidContract);
    }
    Ok(())
}

pub(super) fn validate_now(context: &PermissionControlContextV1, now: u64) -> Result<(), Error> {
    if !finite(now) || now < context.issued_at_unix_ms || now >= context.expires_at_unix_ms {
        return Err(Error::Expired);
    }
    Ok(())
}
