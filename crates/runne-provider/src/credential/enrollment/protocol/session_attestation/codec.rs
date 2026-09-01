use ring::signature;

use super::{
    CredentialIssueTicketBindingV1, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionProcessClaimsV1, CredentialWriterSessionRuntimeClaimsV1,
    CredentialWriterSessionTicketClaimsV1, SignedCredentialWriterSessionAttestationV1,
};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialInstallationOwnerId,
    CredentialOperationId, CredentialTicketAttempt,
};

const DOMAIN: &[u8] = b"GOCODE_PROVIDER_CREDENTIAL_WRITER_SESSION_ATTESTATION_V1\0";
const VERSION: u8 = 1;
const SEQUENCE: u64 = 0;
const SIGNED_BYTES: usize = 577;
const BYTES: usize = 641;

/// Exact codec whose verifier requires an independently authenticated public key.
pub struct CredentialWriterSessionAttestationCodec;

impl CredentialWriterSessionAttestationCodec {
    /// Exact signed-record byte length.
    pub const BYTES: usize = BYTES;

    /// Encodes the record in its sole canonical fixed-width form.
    #[must_use]
    pub fn encode(value: &SignedCredentialWriterSessionAttestationV1) -> [u8; BYTES] {
        let ticket = &value.claims.ticket;
        let runtime = &value.claims.runtime;
        let process = &value.claims.process;
        let mut bytes = [0; BYTES];
        bytes[0] = VERSION;
        bytes[1..17].copy_from_slice(&ticket.operation.as_bytes());
        bytes[17..25].copy_from_slice(&ticket.attempt.get().to_be_bytes());
        bytes[25..57].copy_from_slice(&ticket.issue_ticket.digest().as_bytes());
        bytes[57..89].copy_from_slice(&ticket.claim.as_bytes());
        bytes[89..121].copy_from_slice(&ticket.owner.as_bytes());
        bytes[121..153].copy_from_slice(&ticket.begin_proof.as_bytes());
        bytes[153..185].copy_from_slice(&runtime.protected_session.as_bytes());
        bytes[185..217].copy_from_slice(&runtime.tauri_peer.as_bytes());
        bytes[217..249].copy_from_slice(&runtime.daemon_authority.as_bytes());
        bytes[249..257].copy_from_slice(&runtime.database_generation.to_be_bytes());
        bytes[257..265].copy_from_slice(&runtime.supervisor_generation.to_be_bytes());
        bytes[265..297].copy_from_slice(&runtime.release_tuple.as_bytes());
        bytes[297..305].copy_from_slice(&ticket.issued_at.to_be_bytes());
        bytes[305..313].copy_from_slice(&ticket.expires_at.to_be_bytes());
        bytes[313..345].copy_from_slice(&value.channel.as_bytes());
        bytes[345..377].copy_from_slice(&value.publication_public_key);
        bytes[377..409].copy_from_slice(&process.handoff.as_bytes());
        bytes[409..441].copy_from_slice(&process.writer_start.as_bytes());
        bytes[441..473].copy_from_slice(&process.writer_image.as_bytes());
        bytes[473..505].copy_from_slice(&process.writer_ownership.as_bytes());
        bytes[505..537].copy_from_slice(&process.daemon_start.as_bytes());
        bytes[537..569].copy_from_slice(&process.daemon_image.as_bytes());
        bytes[569..577].copy_from_slice(&SEQUENCE.to_be_bytes());
        bytes[577..].copy_from_slice(&value.signature);
        bytes
    }

    /// Decodes only after verification against the caller's authenticated expected key.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_public_key: [u8; 32],
    ) -> Result<SignedCredentialWriterSessionAttestationV1, CredentialEnrollmentError> {
        if bytes.len() != BYTES
            || bytes[0] != VERSION
            || bytes[569..577] != SEQUENCE.to_be_bytes()
            || expected_public_key == [0; 32]
            || bytes[345..377] != expected_public_key
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let operation = CredentialOperationId::from_bytes(fixed(bytes, 1)?)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let attempt = CredentialTicketAttempt::new(u64::from_be_bytes(fixed(bytes, 17)?))
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let claim = digest(fixed(bytes, 57)?)?;
        let channel = digest(fixed(bytes, 313)?)?;
        let issue_ticket = CredentialIssueTicketBindingV1::from_attested_digest(
            fixed(bytes, 25)?,
            operation,
            attempt,
            claim,
            channel,
        )?;
        let ticket = CredentialWriterSessionTicketClaimsV1::new(
            operation,
            attempt,
            issue_ticket,
            claim,
            CredentialInstallationOwnerId::from_bytes(fixed(bytes, 89)?)
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
            digest(fixed(bytes, 121)?)?,
            i64::from_be_bytes(fixed(bytes, 297)?),
            i64::from_be_bytes(fixed(bytes, 305)?),
        )
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let runtime = CredentialWriterSessionRuntimeClaimsV1::new(
            digest(fixed(bytes, 153)?)?,
            digest(fixed(bytes, 185)?)?,
            digest(fixed(bytes, 217)?)?,
            u64::from_be_bytes(fixed(bytes, 249)?),
            u64::from_be_bytes(fixed(bytes, 257)?),
            digest(fixed(bytes, 265)?)?,
        )
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let process = CredentialWriterSessionProcessClaimsV1::new(
            digest(fixed(bytes, 377)?)?,
            digest(fixed(bytes, 409)?)?,
            digest(fixed(bytes, 441)?)?,
            digest(fixed(bytes, 473)?)?,
            digest(fixed(bytes, 505)?)?,
            digest(fixed(bytes, 537)?)?,
        )
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, expected_public_key)
            .verify(
                &[DOMAIN, &bytes[..SIGNED_BYTES]].concat(),
                &bytes[SIGNED_BYTES..],
            )
            .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?;
        Ok(SignedCredentialWriterSessionAttestationV1 {
            claims: CredentialWriterSessionAttestationClaimsV1::new(ticket, runtime, process),
            channel,
            publication_public_key: expected_public_key,
            signature: fixed(bytes, 577)?,
        })
    }
}

pub(super) fn signature_message(value: &SignedCredentialWriterSessionAttestationV1) -> Vec<u8> {
    let bytes = CredentialWriterSessionAttestationCodec::encode(value);
    [DOMAIN, &bytes[..SIGNED_BYTES]].concat()
}

fn digest(value: [u8; 32]) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
    CredentialBindingDigest::from_measured(value)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}

fn fixed<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CredentialEnrollmentError> {
    bytes
        .get(offset..offset + N)
        .ok_or(CredentialEnrollmentError::InvalidFrame)?
        .try_into()
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}
