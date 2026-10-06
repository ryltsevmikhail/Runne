use runne_domain::id::IntegrityDigest;

pub(super) fn issued_row_from_sql(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<super::super::IssuedRow> {
    Ok(super::super::IssuedRow {
        request_digest: fixed_digest(row.get(0)?)?,
        state: row.get(1)?,
        expires_at: row.get(2)?,
        challenge_id: fixed_array(row.get(3)?)?,
        nonce: fixed_array(row.get(4)?)?,
        challenge_digest: fixed_digest(row.get(5)?)?,
    })
}

pub(super) fn issued_full_row_from_sql(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<super::super::IssuedChallengeRow> {
    Ok(super::super::IssuedChallengeRow {
        challenge_id: fixed_array(row.get(0)?)?,
        nonce: fixed_array(row.get(1)?)?,
        digest: fixed_digest(row.get(2)?)?,
        request_digest: fixed_digest(row.get(3)?)?,
        command_id: row.get(4)?,
        runtime_authority_id: row.get(5)?,
        principal_id: row.get(6)?,
        workspace_id: row.get(7)?,
        project_id: row.get(8)?,
        workspace_version: row.get(9)?,
        idempotency_key: row.get(10)?,
        store_authority_id: row.get(11)?,
        store_lineage_id: row.get(12)?,
        expected_revision: row.get(13)?,
        preset_version: row.get(14)?,
        managed_epoch: row.get(15)?,
        managed_revision: row.get(16)?,
        managed_status: row.get(17)?,
        managed_deny_mask: row.get(18)?,
        managed_digest: row.get(19)?,
        mode_expires_at: row.get(20)?,
        launch_authority_id: row.get(21)?,
        desktop_host_instance_id: row.get(22)?,
        daemon_instance_id: row.get(23)?,
        launch_generation: row.get(24)?,
        native_key_epoch: row.get(25)?,
        warning_version: row.get(26)?,
        issued_at: row.get(27)?,
        expires_at: row.get(28)?,
        state: row.get(29)?,
        proof_identifier: row.get(30)?,
        consumed_at: row.get(31)?,
    })
}

pub(super) fn fixed_array<const N: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn fixed_digest(value: Vec<u8>) -> rusqlite::Result<IntegrityDigest> {
    Ok(IntegrityDigest::from_bytes(fixed_array(value)?))
}
