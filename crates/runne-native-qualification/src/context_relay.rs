use std::fmt;

use runne_api::{
    ProtectedActivationKeys, QualificationRunContextRelayAuthenticator,
    QualificationRunContextRelayBindingV1, QualificationRunContextRelayContentBindingV1,
    QualificationRunContextRelayDirectionV1,
};
use sha2::{Digest as _, Sha256};

use crate::{MAX_RUN_CONTEXT_BYTES, PendingQualificationRunContext};

const MAGIC: &[u8; 8] = b"RNQCTX1\0";
const VERSION: u8 = 1;
const FIXED_PREFIX_BYTES: usize = 78;
const MAC_BYTES: usize = 32;

/// Closed runner-context relay rejection without context or binding detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationRunContextRelayError;

impl fmt::Display for QualificationRunContextRelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification run-context relay rejected")
    }
}

impl std::error::Error for QualificationRunContextRelayError {}

/// Version-1 bounded signed runner-context codec.
pub struct QualificationRunContextRelayCodecV1 {
    authenticator: QualificationRunContextRelayAuthenticator,
}

impl QualificationRunContextRelayCodecV1 {
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self {
            authenticator: QualificationRunContextRelayAuthenticator::from_protected_activation(
                keys,
            ),
        }
    }

    /// Routing hint for one length-prefixed protected-channel frame.
    /// Authentication and exact binding checks remain mandatory after this hint.
    #[must_use]
    pub fn recognizes_frame(frame: &[u8]) -> bool {
        frame.get(4..12) == Some(MAGIC.as_slice())
    }

    pub(crate) fn encode_context(
        &self,
        binding: &QualificationRunContextRelayBindingV1,
        context_bytes: &[u8],
    ) -> Result<Vec<u8>, QualificationRunContextRelayError> {
        let authenticated_content = content_binding(context_bytes)?;
        let mut frame = Vec::with_capacity(FIXED_PREFIX_BYTES + context_bytes.len() + MAC_BYTES);
        frame.extend_from_slice(MAGIC);
        frame.push(VERSION);
        frame.push(binding.direction().wire_tag());
        frame.extend_from_slice(&binding.protected_session_id());
        frame.extend_from_slice(&binding.release_tuple_v3_sha256());
        frame.extend_from_slice(&binding.launch_generation().to_be_bytes());
        frame.extend_from_slice(&binding.sequence().to_be_bytes());
        frame.extend_from_slice(
            &u32::try_from(context_bytes.len())
                .map_err(|_| QualificationRunContextRelayError)?
                .to_be_bytes(),
        );
        frame.extend_from_slice(context_bytes);
        frame.extend_from_slice(
            &self
                .authenticator
                .authenticate(binding, &authenticated_content),
        );
        Ok(frame)
    }

    /// Decodes only a frame matching the exact independently supplied binding.
    ///
    /// # Errors
    ///
    /// Rejects any authentication, context, version, direction, length, bound,
    /// canonical-context, or framing mismatch.
    pub fn decode(
        &self,
        frame: &[u8],
        expected: &QualificationRunContextRelayBindingV1,
    ) -> Result<PendingQualificationRunContext, QualificationRunContextRelayError> {
        if frame.len() < FIXED_PREFIX_BYTES + 1 + MAC_BYTES
            || frame.get(..8) != Some(MAGIC.as_slice())
            || frame[8] != VERSION
        {
            return Err(QualificationRunContextRelayError);
        }
        let direction = QualificationRunContextRelayDirectionV1::from_wire_tag(frame[9])
            .ok_or(QualificationRunContextRelayError)?;
        let observed = QualificationRunContextRelayBindingV1::new(
            take::<16>(frame, 10)?,
            take::<32>(frame, 26)?,
            u64::from_be_bytes(take::<8>(frame, 58)?),
            direction,
            u64::from_be_bytes(take::<8>(frame, 66)?),
        )
        .map_err(|_| QualificationRunContextRelayError)?;
        if &observed != expected {
            return Err(QualificationRunContextRelayError);
        }
        let length = usize::try_from(u32::from_be_bytes(take::<4>(frame, 74)?))
            .map_err(|_| QualificationRunContextRelayError)?;
        if !(1..=MAX_RUN_CONTEXT_BYTES).contains(&length)
            || frame.len() != FIXED_PREFIX_BYTES + length + MAC_BYTES
        {
            return Err(QualificationRunContextRelayError);
        }
        let context_bytes = &frame[FIXED_PREFIX_BYTES..FIXED_PREFIX_BYTES + length];
        let authenticated_content = content_binding(context_bytes)?;
        let proof = take::<32>(frame, FIXED_PREFIX_BYTES + length)?;
        if !self
            .authenticator
            .verifies(&observed, &authenticated_content, &proof)
        {
            return Err(QualificationRunContextRelayError);
        }
        PendingQualificationRunContext::from_admitted_frame(context_bytes.to_vec())
            .map_err(|_| QualificationRunContextRelayError)
    }
}

fn content_binding(
    context_bytes: &[u8],
) -> Result<QualificationRunContextRelayContentBindingV1, QualificationRunContextRelayError> {
    QualificationRunContextRelayContentBindingV1::new(
        u32::try_from(context_bytes.len()).map_err(|_| QualificationRunContextRelayError)?,
        Sha256::digest(context_bytes).into(),
    )
    .map_err(|_| QualificationRunContextRelayError)
}

fn take<const N: usize>(
    frame: &[u8],
    offset: usize,
) -> Result<[u8; N], QualificationRunContextRelayError> {
    frame
        .get(offset..offset + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(QualificationRunContextRelayError)
}
