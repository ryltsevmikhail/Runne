use runne_application::project_trust::admin::{AdminError, ManagedPolicyAdminReceipt};
use rusqlite::{Connection, OptionalExtension, params};

use super::identity::AdminIdentity;

pub(super) fn load_receipt(
    connection: &Connection,
    command_id: &[u8; 16],
    identity: &AdminIdentity,
    expected_digest: Option<&[u8; 32]>,
) -> Result<Option<ManagedPolicyAdminReceipt>, AdminError> {
    let raw = connection
        .query_row(
            "SELECT idempotency_key, stable_subject_digest, authority_id, lineage_id, project_id,
                instance_epoch, prior_revision, revision, old_rules_digest, new_rules_digest,
                command_digest, committed_at_unix_ms
         FROM managed_policy_admin_receipts WHERE command_id=?1",
            params![command_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()
        .map_err(|_| AdminError::Unavailable)?;
    let Some(row) = raw else { return Ok(None) };
    let subject = fixed(row.1)?;
    let authority = fixed(row.2)?;
    let lineage = fixed(row.3)?;
    let command_digest = fixed(row.10)?;
    if subject != identity.stable_digest
        || authority != identity.authority_id
        || lineage != identity.lineage_id
        || expected_digest.is_some_and(|value| *value != command_digest)
    {
        return Err(AdminError::Conflict);
    }
    Ok(Some(ManagedPolicyAdminReceipt::from_persisted(
        *command_id,
        row.0,
        subject,
        authority,
        lineage,
        fixed(row.4)?,
        u64::try_from(row.5).map_err(|_| AdminError::Unavailable)?,
        u64::try_from(row.6).map_err(|_| AdminError::Unavailable)?,
        u64::try_from(row.7).map_err(|_| AdminError::Unavailable)?,
        fixed(row.8)?,
        fixed(row.9)?,
        command_digest,
        row.11,
    )?))
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], AdminError> {
    value.try_into().map_err(|_| AdminError::Unavailable)
}
