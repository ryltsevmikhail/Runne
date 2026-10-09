use super::decisions::{assert_decision_conflict, assert_persisted_decision};
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn opposite_approval_decisions_conflict_and_preserve_the_first_decision() {
    for (case, (winner, opposite)) in [
        (ApprovalDecision::Approve, ApprovalDecision::Deny),
        (ApprovalDecision::Deny, ApprovalDecision::Approve),
    ]
    .into_iter()
    .enumerate()
    {
        let approval_id = ApprovalId::from_bytes(id(0x80 + case as u8));
        let database = support::Database::new("approval-opposite-decisions");
        let repository = database.repository();
        repository
            .create_pending_approval(create_command(approval_id, "execute"))
            .await
            .unwrap();

        let winner_context = context(0x90 + case as u8, "approval-winner");
        let winner_command = request_decision(approval_id, winner);
        let first_ack = repository
            .decide_approval(winner_context.clone(), winner_command.clone())
            .await
            .unwrap();
        let winner_state = match winner {
            ApprovalDecision::Approve => ApprovalState::Approved,
            ApprovalDecision::Deny => ApprovalState::Denied,
        };
        assert_eq!(
            (
                first_ack.approval_id(),
                first_ack.task_run_id(),
                first_ack.state(),
                first_ack.new_version()
            ),
            (
                approval_id,
                TaskRunId::from_bytes(id(0x71)),
                winner_state,
                2
            )
        );
        assert_decision_conflict(
            &repository,
            winner_context.clone(),
            request_decision(approval_id, opposite),
        )
        .await;
        assert_decision_conflict(
            &repository,
            context(0xa0 + case as u8, "approval-opposite-fresh"),
            request_decision(approval_id, opposite),
        )
        .await;
        for changed_binding in changed_binding_decisions(approval_id, winner) {
            assert_decision_conflict(&repository, winner_context.clone(), changed_binding).await;
        }

        let query_context = ApprovalQueryContext {
            principal: ApiPrincipalId::new("owner").unwrap(),
        };
        let before_replay = repository
            .get_approval(query_context.clone(), approval_id)
            .await
            .unwrap();
        assert_eq!(
            (before_replay.state(), before_replay.request_version()),
            (winner_state, 2)
        );
        assert_eq!(
            repository
                .decide_approval(winner_context.clone(), winner_command.clone())
                .await
                .unwrap(),
            first_ack
        );
        assert_eq!(
            repository
                .get_approval(query_context.clone(), approval_id)
                .await
                .unwrap(),
            before_replay
        );
        assert_persisted_decision(&database, approval_id, &winner_context, winner);

        drop(repository);
        let reopened_repository = database.reopen();
        assert_decision_conflict(
            &reopened_repository,
            context(0xb0 + case as u8, "approval-opposite-after-reopen"),
            request_decision(approval_id, opposite),
        )
        .await;
        for changed_binding in changed_binding_decisions(approval_id, winner) {
            assert_decision_conflict(
                &reopened_repository,
                winner_context.clone(),
                changed_binding,
            )
            .await;
        }
        assert_eq!(
            reopened_repository
                .get_approval(query_context.clone(), approval_id)
                .await
                .unwrap(),
            before_replay
        );
        assert_eq!(
            reopened_repository
                .decide_approval(winner_context.clone(), winner_command)
                .await
                .unwrap(),
            first_ack
        );
        assert_eq!(
            reopened_repository
                .get_approval(query_context, approval_id)
                .await
                .unwrap(),
            before_replay
        );
        assert_persisted_decision(&database, approval_id, &winner_context, winner);
    }
}
