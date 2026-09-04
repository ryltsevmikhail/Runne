use crate::{CredentialVersionRef, ProviderId};

use super::{CredentialBrokerCommand, CredentialBrokerTarget};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, WriterIdentityMigrationPhase,
};

/// Strict custom codec for canonical broker commands.
pub struct CredentialBrokerCommandCodec;

impl CredentialBrokerCommandCodec {
    /// The only accepted command codec version.
    pub const VERSION: u8 = 1;
    /// Bounded command size; commands contain metadata only.
    pub const MAX_COMMAND_BYTES: usize = 512;

    /// Encodes one command in fixed field order without Serde.
    pub fn encode(command: &CredentialBrokerCommand) -> Result<Vec<u8>, CredentialEnrollmentError> {
        let mut bytes = vec![Self::VERSION];
        bytes.extend_from_slice(&command.operation_id().as_bytes());
        bytes.extend_from_slice(&command.ticket_attempt().get().to_be_bytes());
        put_provider(&mut bytes, command.provider())?;
        bytes.push(command.action() as u8);
        put_target(&mut bytes, command.target())?;
        bytes.extend_from_slice(&command.expected_lifecycle_revision().get().to_be_bytes());
        bytes.extend_from_slice(&command.expected_prior_fence().get().to_be_bytes());
        if let Some(binding) = command.migration_binding() {
            bytes.push(1);
            bytes.extend_from_slice(&binding.as_bytes());
        } else {
            bytes.push(0);
        }
        if bytes.len() > Self::MAX_COMMAND_BYTES {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(bytes)
    }

    /// Decodes one exact, bounded command and rejects alternate representations.
    pub fn decode(bytes: &[u8]) -> Result<CredentialBrokerCommand, CredentialEnrollmentError> {
        if bytes.len() < 2 || bytes.len() > Self::MAX_COMMAND_BYTES || bytes[0] != Self::VERSION {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let mut cursor = 1;
        let operation_id = read_id(bytes, &mut cursor)?;
        let ticket_attempt = read_attempt(bytes, &mut cursor)?;
        let provider = read_provider(bytes, &mut cursor)?;
        let action = read_action(read_byte(bytes, &mut cursor)?)?;
        let target = read_target(bytes, &mut cursor)?;
        let revision = CredentialLifecycleRevision::new(read_number(bytes, &mut cursor)?)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let fence = CredentialFence::new(read_number(bytes, &mut cursor)?)
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
        let migration_binding = match read_byte(bytes, &mut cursor)? {
            0 => None,
            1 => Some(read_digest(bytes, &mut cursor)?),
            _ => return Err(CredentialEnrollmentError::InvalidFrame),
        };
        if cursor != bytes.len() {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        CredentialBrokerCommand::new(
            operation_id,
            ticket_attempt,
            provider,
            action,
            target,
            revision,
            fence,
            migration_binding,
        )
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
    }
}

fn put_provider(bytes: &mut Vec<u8>, value: &ProviderId) -> Result<(), CredentialEnrollmentError> {
    bytes.push(
        u8::try_from(value.as_str().len()).map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    );
    bytes.extend_from_slice(value.as_str().as_bytes());
    Ok(())
}
fn put_target(
    bytes: &mut Vec<u8>,
    value: &CredentialBrokerTarget,
) -> Result<(), CredentialEnrollmentError> {
    match value {
        CredentialBrokerTarget::Version(reference) => {
            bytes.push(1);
            put_reference(bytes, reference)?;
        }
        CredentialBrokerTarget::LegacyImport(reference) => {
            bytes.push(2);
            put_reference(bytes, reference)?;
        }
        CredentialBrokerTarget::LegacySource => bytes.push(3),
        CredentialBrokerTarget::ExactLegacySource(binding) => {
            bytes.push(5);
            bytes.extend_from_slice(&binding.import_operation_id().as_bytes());
            bytes.extend_from_slice(&binding.import_lifecycle_revision().get().to_be_bytes());
            bytes.extend_from_slice(&binding.import_fence().get().to_be_bytes());
            put_reference(bytes, binding.destination())?;
            bytes.extend_from_slice(&binding.observation_digest().as_bytes());
        }
        CredentialBrokerTarget::Migration {
            migration_id,
            phase,
        } => {
            bytes.push(4);
            bytes.extend_from_slice(&migration_id.as_bytes());
            bytes.push(*phase as u8);
        }
    }
    Ok(())
}
fn put_reference(
    bytes: &mut Vec<u8>,
    value: &CredentialVersionRef,
) -> Result<(), CredentialEnrollmentError> {
    put_provider(bytes, value.provider())?;
    bytes.extend_from_slice(&value.version().to_be_bytes());
    bytes.extend_from_slice(value.ref_digest());
    Ok(())
}
fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], CredentialEnrollmentError> {
    let end = cursor
        .checked_add(length)
        .ok_or(CredentialEnrollmentError::InvalidFrame)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(CredentialEnrollmentError::InvalidFrame)?;
    *cursor = end;
    Ok(value)
}
fn read_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, CredentialEnrollmentError> {
    take(bytes, cursor, 1)?
        .first()
        .copied()
        .ok_or(CredentialEnrollmentError::InvalidFrame)
}
fn read_number(bytes: &[u8], cursor: &mut usize) -> Result<u64, CredentialEnrollmentError> {
    Ok(u64::from_be_bytes(
        take(bytes, cursor, 8)?
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    ))
}
fn read_id(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialOperationId, CredentialEnrollmentError> {
    CredentialOperationId::from_bytes(
        take(bytes, cursor, 16)?
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    )
    .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}
fn read_attempt(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialTicketAttempt, CredentialEnrollmentError> {
    CredentialTicketAttempt::new(read_number(bytes, cursor)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}
fn read_digest(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
    CredentialBindingDigest::from_measured(
        take(bytes, cursor, 32)?
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    )
    .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}
fn read_provider(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<ProviderId, CredentialEnrollmentError> {
    let length = usize::from(read_byte(bytes, cursor)?);
    let value = std::str::from_utf8(take(bytes, cursor, length)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    ProviderId::new(value).map_err(|_| CredentialEnrollmentError::InvalidFrame)
}
fn read_target(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialBrokerTarget, CredentialEnrollmentError> {
    match read_byte(bytes, cursor)? {
        1 => Ok(CredentialBrokerTarget::Version(read_reference(
            bytes, cursor,
        )?)),
        2 => Ok(CredentialBrokerTarget::LegacyImport(read_reference(
            bytes, cursor,
        )?)),
        3 => Ok(CredentialBrokerTarget::LegacySource),
        5 => {
            let operation = read_id(bytes, cursor)?;
            let revision = CredentialLifecycleRevision::new(read_number(bytes, cursor)?)
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
            let fence = CredentialFence::new(read_number(bytes, cursor)?)
                .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
            let destination = read_reference(bytes, cursor)?;
            let observation = read_digest(bytes, cursor)?;
            Ok(CredentialBrokerTarget::ExactLegacySource(
                crate::CredentialLegacyCleanupBinding::from_parts(
                    operation,
                    revision,
                    fence,
                    destination,
                    observation,
                ),
            ))
        }
        4 => Ok(CredentialBrokerTarget::Migration {
            migration_id: read_id(bytes, cursor)?,
            phase: read_phase(read_byte(bytes, cursor)?)?,
        }),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}
fn read_reference(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CredentialVersionRef, CredentialEnrollmentError> {
    let provider = read_provider(bytes, cursor)?;
    let version = read_number(bytes, cursor)?;
    let encoded_digest = take(bytes, cursor, 32)?;
    let reference = CredentialVersionRef::new(provider, version)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    if reference.ref_digest().as_slice() != encoded_digest {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    Ok(reference)
}
fn read_action(value: u8) -> Result<CredentialOperationAction, CredentialEnrollmentError> {
    match value {
        1 => Ok(CredentialOperationAction::Pair),
        2 => Ok(CredentialOperationAction::Revoke),
        3 => Ok(CredentialOperationAction::MigrateLegacy),
        4 => Ok(CredentialOperationAction::RetiredVersionCleanup),
        5 => Ok(CredentialOperationAction::LegacySourceCleanup),
        6 => Ok(CredentialOperationAction::WriterIdentityMigrationEffect),
        7 => Ok(CredentialOperationAction::WriterIdentityMigrationVerify),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}
fn read_phase(value: u8) -> Result<WriterIdentityMigrationPhase, CredentialEnrollmentError> {
    match value {
        1 => Ok(WriterIdentityMigrationPhase::OldWriterEffect),
        2 => Ok(WriterIdentityMigrationPhase::NewWriterVerify),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}
