use std::fmt;

use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    PermissionControlContextV1, PermissionControlModeConsentV1, PermissionControlPayloadV1,
    PermissionControlPurposeV1,
};

type HmacSha256 = Hmac<sha2::Sha256>;
const KEY_IDENTITY_DOMAIN: &[u8] = b"runne:protected:permission-control:key-identity:v1\0";
const CONSENT_KEY_DOMAIN: &[u8] =
    b"runne:protected:permission-control:native-consent-attestation:v1";
const CONSENT_MESSAGE_DOMAIN: &[u8] =
    b"runne:protected:permission-control:native-consent-attestation:v1\0";

/// Fixed-purpose transcript authentication failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionControlNativeErrorV1 {
    InvalidTranscript,
}

/// Opaque fixed-purpose authenticator. It authenticates only a closed native
/// mode-consent transcript; it cannot construct application-verified consent.
pub struct PermissionControlNativeAuthenticatorV1 {
    key_identity: Zeroizing<[u8; 32]>,
    consent_key: Zeroizing<[u8; 32]>,
    native_key_epoch: u64,
}

impl PermissionControlNativeAuthenticatorV1 {
    pub(crate) fn from_readiness_key(readiness: &[u8; 32], native_key_epoch: u64) -> Self {
        let mut identity = HmacSha256::new_from_slice(readiness).expect("fixed HMAC key");
        identity.update(KEY_IDENTITY_DOMAIN);
        Self {
            key_identity: Zeroizing::new(identity.finalize().into_bytes().into()),
            consent_key: Zeroizing::new(super::super::derive_key(readiness, CONSENT_KEY_DOMAIN)),
            native_key_epoch,
        }
    }

    /// Epoch bound to the protected key installation that created this owner.
    #[must_use]
    pub const fn native_key_epoch(&self) -> u64 {
        self.native_key_epoch
    }

    /// Compares private owner identity without exposing its digest.
    pub fn has_same_key_identity(&self, other: &Self) -> bool {
        bool::from(
            self.key_identity
                .as_ref()
                .ct_eq(other.key_identity.as_ref()),
        )
    }

    /// Computes the dedicated tag over one closed mode-consent transcript.
    /// The native caller must first consume its one-use warning token and, for
    /// FullAccess, fresh OS reauthentication. This cryptographic tag alone is
    /// never an application proof receipt.
    pub fn authenticate_mode_consent(
        &self,
        context: &PermissionControlContextV1,
        consent: &PermissionControlModeConsentV1,
    ) -> Result<[u8; 32], PermissionControlNativeErrorV1> {
        if context.native_key_epoch != self.native_key_epoch {
            return Err(PermissionControlNativeErrorV1::InvalidTranscript);
        }
        validate(context, consent)?;
        let mut mac = HmacSha256::new_from_slice(&self.consent_key[..]).expect("fixed HMAC key");
        mac.update(CONSENT_MESSAGE_DOMAIN);
        transcript(&mut mac, context, consent);
        Ok(mac.finalize().into_bytes().into())
    }

    /// Verifies a received native tag using constant-time comparison.
    pub fn verify_mode_consent(
        &self,
        context: &PermissionControlContextV1,
        consent: &PermissionControlModeConsentV1,
    ) -> Result<(), PermissionControlNativeErrorV1> {
        let expected = self.authenticate_mode_consent(context, consent)?;
        bool::from(expected.as_slice().ct_eq(&consent.warning_attestation))
            .then_some(())
            .ok_or(PermissionControlNativeErrorV1::InvalidTranscript)
    }
}

impl fmt::Debug for PermissionControlNativeAuthenticatorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PermissionControlNativeAuthenticatorV1(<redacted>)")
    }
}

fn validate(
    context: &PermissionControlContextV1,
    consent: &PermissionControlModeConsentV1,
) -> Result<(), PermissionControlNativeErrorV1> {
    super::validation::validate_context(context, super::PermissionControlPhaseV1::Consent)
        .map_err(|_| PermissionControlNativeErrorV1::InvalidTranscript)?;
    super::validation::validate_payload(
        PermissionControlPurposeV1::ModeControl,
        &PermissionControlPayloadV1::ModeConsent(consent.clone()),
        context,
    )
    .map_err(|_| PermissionControlNativeErrorV1::InvalidTranscript)
}

fn transcript(
    mac: &mut HmacSha256,
    context: &PermissionControlContextV1,
    consent: &PermissionControlModeConsentV1,
) {
    text(mac, &context.runtime_authority);
    mac.update(&context.store_lineage_id);
    mac.update(&context.stable_subject_digest);
    mac.update(&context.protected_launch_authority_id);
    mac.update(&context.desktop_authority_id);
    mac.update(&context.daemon_instance_id);
    mac.update(&context.protected_session_id);
    mac.update(&context.launch_generation.to_be_bytes());
    mac.update(&context.native_key_epoch.to_be_bytes());
    mac.update(&context.command_id);
    text(mac, &context.idempotency_key);
    mac.update(&context.public_request_digest);
    mac.update(&context.predecessor_transcript_digest);
    mac.update(&context.issued_at_unix_ms.to_be_bytes());
    mac.update(&context.expires_at_unix_ms.to_be_bytes());
    mac.update(&consent.challenge_id);
    mac.update(&consent.public_request_digest);
    mac.update(&consent.issued_challenge_binding_digest);
    mac.update(&consent.native_warning_version.to_be_bytes());
    mac.update(&[match consent.requested_mode {
        super::PermissionModeSelectionV1::AskAlways => 1,
        super::PermissionModeSelectionV1::RiskBased => 2,
        super::PermissionModeSelectionV1::FullAccess => 3,
    }]);
    mac.update(&consent.confirmed_binding_digest);
    // Consent is the only positive decision encoded by this transcript.
    mac.update(&[1]);
    match &consent.os_attestation {
        super::ModeOsAttestationV1::NotRequired => mac.update(&[0]),
        super::ModeOsAttestationV1::Fresh {
            qualified_fingerprint,
            authenticated_at_unix_ms,
        } => {
            mac.update(&[1]);
            mac.update(qualified_fingerprint);
            mac.update(&authenticated_at_unix_ms.to_be_bytes());
        }
    }
}

fn text(mac: &mut HmacSha256, value: &str) {
    let length = u16::try_from(value.len()).expect("validated bounded text");
    mac.update(&length.to_be_bytes());
    mac.update(value.as_bytes());
}

#[cfg(test)]
#[path = "native_auth_tests.rs"]
mod tests;
