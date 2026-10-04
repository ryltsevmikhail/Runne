fn principal_digest(principal: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(b"runne-unknown-successor-principal\x01")
        .chain_update((principal.len() as u64).to_be_bytes())
        .chain_update(principal.as_bytes())
        .finalize()
        .into()
}

fn v57_release_event_matches(connection: &Connection, row: &SuccessorRow) -> SqliteResult<bool> {
    if row.release_reason == "user_supersession" {
        let (Some(prior_id), Some(prior_version)) =
            (row.prior_id.as_deref(), row.prior_version)
        else {
            return Ok(false);
        };
        if prior_id != row.release_id {
            return Ok(false);
        }
        let version: Option<i64> = connection
            .query_row(
                "SELECT sequence FROM events WHERE event_id=?1 AND aggregate_type=1
                 AND aggregate_id=?2",
                rusqlite::params![&row.release_id, &row.predecessor],
                |record| record.get(0),
            )
            .optional()?;
        return Ok(version == Some(row.release_version) && version == Some(prior_version));
    }
    if !matches!(row.release_reason.as_str(), "no_effect_release" | "terminal_settlement") {
        return Ok(false);
    }
    let (Some(prior_id), Some(prior_version)) =
        (row.prior_id.as_deref(), row.prior_version)
    else {
        return Ok(false);
    };
    if prior_id != row.release_id || prior_version != row.release_version {
        return Ok(false);
    }
    let version: Option<i64> = connection
        .query_row(
            "SELECT sequence FROM events WHERE event_id=?1 AND aggregate_type=1
             AND aggregate_id=?2",
            rusqlite::params![&row.release_id, &row.predecessor],
            |record| record.get(0),
        )
        .optional()?;
    Ok(version == Some(row.release_version))
}
