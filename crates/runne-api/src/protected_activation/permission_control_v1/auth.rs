use std::fmt;

use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    PermissionControlContextV1, PermissionControlDirectionV1, PermissionControlErrorV1,
    PermissionControlPayloadV1, PermissionControlPhaseV1, PermissionControlPurposeV1,
};

type HmacSha256 = Hmac<sha2::Sha256>;
const MAC_DOMAIN: &[u8] = b"runne:protected:permission-control:wire:v1\0";
const MODE_DOMAIN: &[u8] = b"runne:protected:mode-control:v1";
const MANAGED_DOMAIN: &[u8] = b"runne:protected:managed-policy-control:v1";

/// HMAC endpoint authenticator. It verifies only transport integrity and freshness.
pub struct PermissionControlAuthenticatorV1 {
    pub(super) purpose: PermissionControlPurposeV1,
    key: Zeroizing<[u8; 32]>,
}

impl PermissionControlAuthenticatorV1 {
    #[must_use]
    pub fn from_protected_activation(
        keys: &super::super::ProtectedActivationKeys,
        purpose: PermissionControlPurposeV1,
    ) -> Self {
        let domain = match purpose {
            PermissionControlPurposeV1::ModeControl => MODE_DOMAIN,
            PermissionControlPurposeV1::ManagedPolicyControl => MANAGED_DOMAIN,
        };
        Self {
            purpose,
            key: Zeroizing::new(super::super::derive_key(keys.readiness_key(), domain)),
        }
    }

    pub const fn purpose(&self) -> PermissionControlPurposeV1 {
        self.purpose
    }

    pub(super) fn authenticate_mac(&self, bytes: &[u8], expected: &[u8]) -> bool {
        let actual = self.mac(bytes);
        bool::from(actual.as_slice().ct_eq(expected))
    }

    pub(super) fn mac(&self, bytes: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key[..]).expect("HMAC accepts a fixed key");
        mac.update(MAC_DOMAIN);
        mac.update(bytes);
        mac.finalize().into_bytes().into()
    }
}

impl fmt::Debug for PermissionControlAuthenticatorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PermissionControlAuthenticatorV1(<redacted>)")
    }
}

impl PermissionControlAuthenticatorV1 {
    /// Verifies the MAC and extracts only the command address from a Mode Request.
    /// This routing hint is not an authenticated frame and does not advance sequence state.
    pub fn mode_request_routing_hint(
        &self,
        bytes: &[u8],
        previous_sequence: u64,
        now_unix_ms: u64,
    ) -> Result<super::PermissionControlRoutingHintV1, PermissionControlErrorV1> {
        self.mode_routing_hint(
            bytes,
            super::PermissionControlPhaseV1::Request,
            previous_sequence,
            now_unix_ms,
        )
    }

    /// Verifies a consent MAC and extracts only its command address.
    pub fn mode_consent_routing_hint(
        &self,
        bytes: &[u8],
        previous_sequence: u64,
        now_unix_ms: u64,
    ) -> Result<super::PermissionControlRoutingHintV1, PermissionControlErrorV1> {
        self.mode_routing_hint(
            bytes,
            super::PermissionControlPhaseV1::Consent,
            previous_sequence,
            now_unix_ms,
        )
    }

    /// Verifies a cancellation MAC and extracts only its command address.
    pub fn mode_cancel_routing_hint(
        &self,
        bytes: &[u8],
        previous_sequence: u64,
        now_unix_ms: u64,
    ) -> Result<super::PermissionControlRoutingHintV1, PermissionControlErrorV1> {
        self.mode_routing_hint(
            bytes,
            super::PermissionControlPhaseV1::Cancel,
            previous_sequence,
            now_unix_ms,
        )
    }

    fn mode_routing_hint(
        &self,
        bytes: &[u8],
        phase: super::PermissionControlPhaseV1,
        previous_sequence: u64,
        now_unix_ms: u64,
    ) -> Result<super::PermissionControlRoutingHintV1, PermissionControlErrorV1> {
        use super::PermissionControlPurposeV1 as Purpose;

        if bytes.len() > super::validation::MAX_FRAME_BYTES || bytes.len() < 4 + 8 + 3 + 8 + 32 {
            return Err(PermissionControlErrorV1::MalformedFrame);
        }
        let declared = u32::from_be_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| PermissionControlErrorV1::MalformedFrame)?,
        ) as usize;
        if declared != bytes.len() {
            return Err(PermissionControlErrorV1::MalformedFrame);
        }
        let mac_at = bytes.len() - 32;
        if !self.authenticate_mac(&bytes[..mac_at], &bytes[mac_at..]) {
            return Err(PermissionControlErrorV1::AuthenticationFailed);
        }
        let decoded = super::decode::decode_unsigned(&bytes[4..mac_at])?;
        if self.purpose != Purpose::ModeControl || decoded.purpose != self.purpose {
            return Err(PermissionControlErrorV1::PurposeMismatch);
        }
        if decoded.payload.phase() != phase {
            return Err(PermissionControlErrorV1::PhaseMismatch);
        }
        if decoded.direction != super::PermissionControlDirectionV1::DesktopToDaemon {
            return Err(PermissionControlErrorV1::DirectionMismatch);
        }
        let mode_payload = matches!(
            (&phase, &decoded.payload),
            (
                super::PermissionControlPhaseV1::Request,
                PermissionControlPayloadV1::ModeRequest(_)
            ) | (
                super::PermissionControlPhaseV1::Consent,
                PermissionControlPayloadV1::ModeConsent(_)
            ) | (
                super::PermissionControlPhaseV1::Cancel,
                PermissionControlPayloadV1::Cancel
            )
        );
        if !mode_payload {
            return Err(PermissionControlErrorV1::PurposeMismatch);
        }
        super::validation::validate_context(&decoded.context, phase)?;
        super::validation::validate_payload(self.purpose, &decoded.payload, &decoded.context)?;
        super::validation::validate_now(&decoded.context, now_unix_ms)?;
        let next = previous_sequence
            .checked_add(1)
            .ok_or(PermissionControlErrorV1::SequenceMismatch)?;
        if decoded.sequence != next {
            return Err(PermissionControlErrorV1::SequenceMismatch);
        }
        Ok(super::PermissionControlRoutingHintV1 {
            command_id: runne_domain::id::CommandId::from_bytes(decoded.context.command_id),
        })
    }

    /// Encodes a closed payload with caller-owned shared-channel sequence.
    pub fn issue_frame(
        &self,
        context: PermissionControlContextV1,
        sequence: u64,
        direction: PermissionControlDirectionV1,
        payload: PermissionControlPayloadV1,
    ) -> Result<Vec<u8>, PermissionControlErrorV1> {
        super::codec::issue(self, context, sequence, direction, payload)
    }

    /// Authenticates exact binding, endpoint, payload phase and next shared sequence.
    /// The expected context comes from the canonical issued ceremony, including its explicit
    /// current session ID; a key epoch never substitutes for that session binding.
    #[allow(clippy::too_many_arguments)]
    pub fn authenticate_frame(
        &self,
        bytes: &[u8],
        expected_context: &PermissionControlContextV1,
        expected_purpose: PermissionControlPurposeV1,
        expected_phase: PermissionControlPhaseV1,
        expected_direction: PermissionControlDirectionV1,
        previous_sequence: u64,
        now_unix_ms: u64,
    ) -> Result<super::AuthenticatedPermissionControlFrameV1, PermissionControlErrorV1> {
        super::codec::authenticate(
            self,
            bytes,
            expected_context,
            expected_purpose,
            expected_phase,
            expected_direction,
            previous_sequence,
            now_unix_ms,
        )
    }
}
