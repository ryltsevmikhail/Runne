use super::*;
use rusqlite::{OptionalExtension, params};

pub(super) struct Candidate {
    pub(super) semantic: Vec<u8>,
    pub(super) principal: String,
    pub(super) conversation: Vec<u8>,
    pub(super) taskrun: Vec<u8>,
    pub(super) attempt: Vec<u8>,
    pub(super) call: Vec<u8>,
    pub(super) idem: String,
    pub(super) digest_version: i64,
    pub(super) prepared: Vec<u8>,
    pub(super) render: Vec<u8>,
    pub(super) profile: Vec<u8>,
    pub(super) pricing: Vec<u8>,
    pub(super) input_tokens: i64,
    pub(super) output_tokens: i64,
    pub(super) max_cost: i64,
    pub(super) currency: String,
    pub(super) dispatch_state: i64,
    pub(super) typed_rejection: Option<i64>,
    pub(super) has_stream: bool,
    pub(super) has_settlement: bool,
    pub(super) has_effect: bool,
    pub(super) has_journal: bool,
    pub(super) has_outbox: bool,
    pub(super) has_accounting: bool,
    pub(super) has_poll: bool,
    pub(super) has_remote_intent: bool,
    pub(super) has_remote_response: bool,
    pub(super) has_disposition: bool,
}

const CANDIDATE_SQL: &str = r#"
SELECT a.semantic_digest,a.principal_id,a.conversation_id,a.taskrun_id,a.execution_attempt_id,
       a.call_id,a.provider_idempotency_key,p.call_digest_version,a.prepared_digest,a.render_digest,
       a.profile_digest,a.pricing_revision_digest,a.requested_input_tokens,a.requested_output_tokens,
       a.max_cost_micros,a.currency,d.state,d.pre_effect_rejection,d.stream_id IS NOT NULL,
       d.settlement_digest IS NOT NULL,
       EXISTS(SELECT 1 FROM provider_effect_starts x WHERE x.dispatch_attempt_id=d.attempt_id),
       EXISTS(SELECT 1 FROM provider_stream_journal x WHERE x.dispatch_attempt_id=d.attempt_id),
       EXISTS(SELECT 1 FROM provider_terminal_outbox x WHERE x.dispatch_attempt_id=d.attempt_id),
       EXISTS(SELECT 1 FROM provider_accounting_settlements x WHERE x.dispatch_attempt_id=d.attempt_id),
       EXISTS(SELECT 1 FROM provider_poll_flights x WHERE x.dispatch_attempt_id=d.attempt_id),
       EXISTS(SELECT 1 FROM provider_remote_request_intents x WHERE x.dispatch_attempt_id=d.attempt_id),
       EXISTS(SELECT 1 FROM provider_remote_response_bindings x WHERE x.dispatch_attempt_id=d.attempt_id),
       EXISTS(SELECT 1 FROM provider_terminal_dispositions x WHERE x.dispatch_attempt_id=d.attempt_id)
FROM provider_execution_admissions a
JOIN provider_prepared_requests p ON p.call_id=a.call_id
 AND p.prepared_digest=a.prepared_digest AND p.render_digest=a.render_digest
 AND p.profile_digest=a.profile_digest
JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id AND d.call_id=a.call_id
 AND d.provider_idempotency_key=a.provider_idempotency_key AND d.fencing_token=a.fencing_token
 AND d.prepared_digest=a.prepared_digest AND d.render_digest=a.render_digest
 AND d.profile_digest=a.profile_digest
JOIN provider_effect_authorities e ON e.authority_id=a.authority_id
 AND e.revision=a.authority_revision AND e.attempt_id=d.attempt_id AND e.permit_id=a.permit_id
 AND e.token_reservation_id=a.token_reservation_id AND e.cost_reservation_id=a.cost_reservation_id
 AND e.prepared_digest=a.prepared_digest AND e.render_digest=a.render_digest
 AND e.profile_digest=a.profile_digest AND e.fencing_token=a.fencing_token
 AND e.owner_id=a.owner_id AND e.scope=a.scope AND e.capability_grant_id=a.capability_grant_id
WHERE a.call_id=?1 AND a.taskrun_id=?2 AND a.execution_attempt_id=?3
 AND a.conversation_id=?4 AND a.principal_id=?5 AND a.runtime_authority_id=?6
 AND d.state=2 AND d.pre_effect_rejection BETWEEN 1 AND 7
 AND NOT EXISTS(SELECT 1 FROM taskrun_provider_round_bindings b WHERE b.call_id=a.call_id)
 AND EXISTS(
   SELECT 1 FROM taskrun_provider_round_bindings b
   JOIN provider_execution_admissions base ON base.call_id=b.call_id
   WHERE b.taskrun_id=a.taskrun_id AND b.fence=?7 AND b.round_index=0
    AND base.runtime_authority_id=a.runtime_authority_id
    AND base.database_generation=a.database_generation AND base.generation=a.generation
    AND base.fencing_token=a.fencing_token AND base.principal_id=a.principal_id
    AND base.conversation_id=a.conversation_id AND base.profile_digest=a.profile_digest
    AND base.pricing_revision_digest=a.pricing_revision_digest
    AND base.owner_id=a.owner_id AND base.scope=a.scope
    AND base.capability_grant_id=a.capability_grant_id
    AND base.capability_revision=a.capability_revision
    AND base.capability_expires_at=a.capability_expires_at
    AND base.capability_revocation_epoch=a.capability_revocation_epoch
    AND base.capability_revocation_observed=a.capability_revocation_observed
    AND base.approval_id=a.approval_id AND base.approval_revision=a.approval_revision
    AND base.approval_expires_at=a.approval_expires_at
    AND base.approval_revocation_epoch=a.approval_revocation_epoch
    AND base.approval_revocation_observed=a.approval_revocation_observed
    AND base.activation_binding_kind=a.activation_binding_kind
    AND base.activation_binding_digest=a.activation_binding_digest)
"#;

#[expect(
    clippy::too_many_arguments,
    reason = "the query binds one candidate to the exact task, attempt, call, and reconstructed origin identity"
)]
pub(super) fn load_candidate(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    evidence: D2ToolLoopCancellationEvidence,
    call: &[u8; 16],
    conversation: &[u8],
    principal: &str,
    runtime: &[u8],
) -> Result<Option<Candidate>, CommitError> {
    let mut statement = connection.prepare(CANDIDATE_SQL).map_err(|_| integrity())?;
    let candidate = statement
        .query_row(
            params![
                call,
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                conversation,
                principal,
                runtime,
                evidence.fence as i64
            ],
            |r| {
                Ok(Candidate {
                    semantic: r.get(0)?,
                    principal: r.get(1)?,
                    conversation: r.get(2)?,
                    taskrun: r.get(3)?,
                    attempt: r.get(4)?,
                    call: r.get(5)?,
                    idem: r.get(6)?,
                    digest_version: r.get(7)?,
                    prepared: r.get(8)?,
                    render: r.get(9)?,
                    profile: r.get(10)?,
                    pricing: r.get(11)?,
                    input_tokens: r.get(12)?,
                    output_tokens: r.get(13)?,
                    max_cost: r.get(14)?,
                    currency: r.get(15)?,
                    dispatch_state: r.get(16)?,
                    typed_rejection: r.get(17)?,
                    has_stream: r.get(18)?,
                    has_settlement: r.get(19)?,
                    has_effect: r.get(20)?,
                    has_journal: r.get(21)?,
                    has_outbox: r.get(22)?,
                    has_accounting: r.get(23)?,
                    has_poll: r.get(24)?,
                    has_remote_intent: r.get(25)?,
                    has_remote_response: r.get(26)?,
                    has_disposition: r.get(27)?,
                })
            },
        )
        .optional()
        .map_err(|_| integrity())?;
    Ok(candidate)
}

pub(super) fn rejected_without_effect(c: &Candidate) -> bool {
    c.dispatch_state == 2
        && c.typed_rejection
            .is_some_and(|reason| (1..=7).contains(&reason))
        && !c.has_stream
        && !c.has_settlement
        && !c.has_effect
        && !c.has_journal
        && !c.has_outbox
        && !c.has_accounting
        && !c.has_poll
        && !c.has_remote_intent
        && !c.has_remote_response
        && !c.has_disposition
}

pub(super) fn verify_origin_claim(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    evidence: D2ToolLoopCancellationEvidence,
    claim_version: u64,
) -> Result<(), CommitError> {
    let version = i64::try_from(claim_version).map_err(|_| integrity())?;
    let exact: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND node_id=?4 AND node_epoch=?5 AND new_version=?6)",
        params![taskrun_id.as_bytes(),attempt_id.as_bytes(),evidence.fence as i64,
            evidence.node_id.as_slice(),evidence.node_epoch as i64,version], |r| r.get(0),
    ).map_err(|_| integrity())?;
    if exact { Ok(()) } else { Err(integrity()) }
}

pub(super) fn round_idempotency_key(call_id: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut key = String::from("gocode-d2-round-");
    for byte in call_id {
        key.push(HEX[(byte >> 4) as usize] as char);
        key.push(HEX[(byte & 0x0f) as usize] as char);
    }
    key
}

fn integrity() -> CommitError {
    super::integrity()
}
