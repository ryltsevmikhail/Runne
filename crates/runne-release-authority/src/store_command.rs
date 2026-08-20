//! Store-owned command fingerprints; callers cannot select replay identity.

use sha2::{Digest as _, Sha256};

use crate::store::CommandFingerprint;
use crate::{AuthorityError, CommandId, Digest, Mutation, PromotionId};

pub fn require_canonical(command: &CommandId) -> Result<(), AuthorityError> {
    command
        .is_canonical()
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)
}

pub fn fingerprint(revision: u64, mutation: &Mutation) -> CommandFingerprint {
    let (kind, commitment) = match mutation {
        Mutation::Ingest { binding, .. } => (b"ingest".as_slice(), binding.sha256()),
        Mutation::QualifyUnsigned { transition } => (
            b"qualify".as_slice(),
            Digest::from_bytes(transition.command_fingerprint()),
        ),
        Mutation::FixtureAuthorizeSigning { transition } => (
            b"authorize-signing".as_slice(),
            Digest::from_bytes(transition.command_fingerprint()),
        ),
        Mutation::VerifySigned { proof } => (b"verify-signed".as_slice(), proof.command_scope()),
        Mutation::FixtureAuthorizePublication { bundle } => (
            b"authorize-publication".as_slice(),
            Digest::from_bytes(Sha256::digest(bundle.command_commitment().as_bytes()).into()),
        ),
        Mutation::StartRc1Review { .. } => (b"start-rc1".as_slice(), Digest::from_bytes([0; 32])),
        Mutation::StartRc3Review { .. } => (b"start-rc3".as_slice(), Digest::from_bytes([0; 32])),
    };
    command_digest(
        b"gocode.release.store-command/1\0",
        &[&revision.to_be_bytes(), kind, &commitment.as_bytes()],
    )
}

pub fn stage_reservation_fingerprint(
    id: &PromotionId,
    revision: u64,
    command: &str,
    kind: runne_promotion_contracts::CanonicalPayloadKind,
) -> [u8; 32] {
    let kind = match kind {
        runne_promotion_contracts::CanonicalPayloadKind::Rc1Decision => b"rc1".as_slice(),
        runne_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => b"rc2".as_slice(),
        runne_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => b"rc3".as_slice(),
    };
    command_digest(
        b"gocode.release.stage-transition-reservation/1\0",
        &[
            id.0.as_bytes(),
            &revision.to_be_bytes(),
            command.as_bytes(),
            kind,
        ],
    )
    .digest()
    .as_bytes()
}

pub fn stage_command_fingerprint(
    revision: u64,
    kind: runne_promotion_contracts::CanonicalPayloadKind,
    admission_fingerprint: [u8; 32],
) -> CommandFingerprint {
    let kind = match kind {
        runne_promotion_contracts::CanonicalPayloadKind::Rc1Decision => b"qualify".as_slice(),
        runne_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => {
            b"authorize-signing".as_slice()
        }
        runne_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => {
            b"authorize-publication".as_slice()
        }
    };
    command_digest(
        b"gocode.release.store-command/1\0",
        &[&revision.to_be_bytes(), kind, &admission_fingerprint],
    )
}

pub fn publication_stage_command_fingerprint(
    revision: u64,
    manifest: Digest,
    destination: &str,
    channel: &str,
    admission_fingerprint: [u8; 32],
) -> CommandFingerprint {
    let commitment = format!(
        "{revision}:{}:{destination}:{channel}:{}",
        manifest.to_hex(),
        crate::threshold_fixture_wire::hex(&admission_fingerprint),
    );
    let commitment = Digest::from_bytes(Sha256::digest(commitment.as_bytes()).into());
    command_digest(
        b"gocode.release.store-command/1\0",
        &[
            &revision.to_be_bytes(),
            b"authorize-publication",
            &commitment.as_bytes(),
        ],
    )
}

pub fn threshold_ack_fingerprint(
    id: &PromotionId,
    revision: u64,
    command: &CommandId,
    admission: Digest,
) -> CommandFingerprint {
    command_digest(
        b"gocode.release.threshold-ack-command/1\0",
        &[
            id.0.as_bytes(),
            &revision.to_be_bytes(),
            command.as_str().as_bytes(),
            &admission.as_bytes(),
        ],
    )
}

pub fn reservation_fingerprint(
    authority_instance: Digest,
    id: &PromotionId,
    revision: u64,
    command: &CommandId,
    authorization: Digest,
    bundle: &crate::FixturePrevalidatedSignedBundle,
) -> CommandFingerprint {
    command_digest(
        b"gocode.release.verify-signed-reservation/1\0",
        &[
            &authority_instance.as_bytes(),
            id.0.as_bytes(),
            &revision.to_be_bytes(),
            command.as_str().as_bytes(),
            &authorization.as_bytes(),
            &bundle.commitment().as_bytes(),
        ],
    )
}

fn command_digest(domain: &[u8], fields: &[&[u8]]) -> CommandFingerprint {
    let mut transcript = domain.to_vec();
    for field in fields {
        transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
        transcript.extend_from_slice(field);
    }
    CommandFingerprint::derived(Digest::from_bytes(Sha256::digest(transcript).into()))
}
