use super::*;

type InvocationRow = (
    Vec<u8>,
    u32,
    String,
    Option<i64>,
    Option<String>,
    Option<i64>,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
);

pub(super) fn verify(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    fence: i64,
    node: &[u8],
    epoch: i64,
) -> Result<(), CommitError> {
    let mut query = connection.prepare(
        "SELECT cycle_id,proposal_index,state,claim_fence,claim_node_id,claim_node_epoch,release_started,
          local_stop_state,managed_area_identity,empty_proof_identity,semantic_digest,result_truncated
         FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 ORDER BY cycle_id,proposal_index",
    ).map_err(|_| invalid())?;
    let rows: Vec<InvocationRow> = query
        .query_map(
            params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                ))
            },
        )
        .map_err(|_| invalid())?
        .collect::<Result<_, _>>()
        .map_err(|_| invalid())?;
    if rows.len() > 2 {
        return Err(invalid());
    }
    for (
        cycle,
        index,
        state,
        claim_fence,
        claim_node,
        claim_epoch,
        release,
        stop,
        area,
        proof,
        semantic,
        truncated,
    ) in rows
    {
        let claimed = match (claim_fence, claim_node.as_deref(), claim_epoch) {
            (Some(f), Some(n), Some(e)) => {
                f == fence
                    && n == uuid::Uuid::from_slice(node)
                        .map_err(|_| invalid())?
                        .to_string()
                    && e == epoch
            }
            (None, None, None) => matches!(state.as_str(), "proposed" | "approved" | "denied"),
            _ => false,
        };
        let area_valid = match (stop, area.as_ref(), proof.as_ref(), semantic.as_ref()) {
            (0, None, None, _) => release == 0,
            (2, Some(a), Some(p), Some(d)) if a == p && d.len() == 32 => {
                let identity =
                    runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(a)
                        .map_err(|_| invalid())?;
                let bytes = identity.to_bytes();
                let cycle: [u8; 16] = cycle.as_slice().try_into().map_err(|_| invalid())?;
                let key = crate::store::taskrun_tool_invocation::ToolInvocationKey {
                    taskrun_id: receipt.taskrun_id,
                    attempt_id: receipt.attempt_id,
                    cycle_id: runne_domain::id::CycleId::from_bytes(cycle),
                    proposal_index: index,
                };
                let digest = runne_domain::id::IntegrityDigest::from_bytes(
                    d.as_slice().try_into().map_err(|_| invalid())?,
                );
                bytes[52..68] == *receipt.taskrun_id.as_bytes()
                    && bytes[68..84] == *receipt.attempt_id.as_bytes()
                    && bytes[84..100] == key.managed_area_nonce(digest)
            }
            _ => false,
        };
        let known = match state.as_str() {
            "proposed" | "approved" | "denied" => stop == 0 && area.is_none() && release == 0,
            "claimed" | "cancelled" => area_valid,
            "uncertain" | "audit_only" => stop == 2 && area_valid,
            "result" => stop == 2 && area_valid && truncated == Some(0),
            _ => false,
        };
        if !claimed || !known {
            return Err(invalid());
        }
    }
    Ok(())
}

fn invalid() -> CommitError {
    super::super::super::parse_helpers::storage_failure(StorageFailureKind::IntegrityViolation)
}
