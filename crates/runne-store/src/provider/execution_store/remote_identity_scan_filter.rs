const SETTLED_REMOTE_ATTEMPT_FILTER: &str = r#"
NOT EXISTS (
  SELECT 1
  FROM provider_remote_terminal_artifacts t
  LEFT JOIN provider_terminal_dispositions d USING(dispatch_attempt_id)
  LEFT JOIN provider_accounting_settlements s USING(dispatch_attempt_id)
  WHERE t.dispatch_attempt_id=q.dispatch_attempt_id
    AND (
      (
        d.disposition=t.disposition AND d.disposition IN (1,2,3,5)
        AND EXISTS (
          SELECT 1
          FROM provider_remote_terminal_settlements x
          JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
          WHERE x.dispatch_attempt_id=q.dispatch_attempt_id
            AND x.taskrun_id=q.taskrun_id
            AND x.taskrun_attempt_id=q.taskrun_attempt_id
            AND x.source_kind=2
            AND x.terminal_status=t.disposition
            AND x.request_digest=q.request_digest
            AND x.response_id_digest=t.response_id_digest
            AND x.artifact_digest=t.plaintext_digest
            AND x.profile_digest=q.profile_digest
            AND x.pricing_revision_digest=q.pricing_revision_digest
            AND x.settlement_state=4
            AND x.application_receipt_digest=o.receipt_digest
            AND o.state=2
            AND NOT EXISTS (
              SELECT 1
              FROM taskrun_provider_cancel_fences c
              WHERE c.dispatch_attempt_id=q.dispatch_attempt_id
                AND c.taskrun_id=q.taskrun_id
                AND c.taskrun_attempt_id=q.taskrun_attempt_id
                AND NOT EXISTS (
                  SELECT 1
                  FROM provider_remote_artifact_cancel_closures z
                  WHERE z.dispatch_attempt_id=q.dispatch_attempt_id
                    AND z.taskrun_id=q.taskrun_id
                    AND z.taskrun_attempt_id=q.taskrun_attempt_id
                    AND z.conversation_id=x.conversation_id
                    AND z.artifact_digest=x.artifact_digest
                    AND z.terminal_status=x.terminal_status
                    AND z.cancellation_event_id=c.cancellation_event_id
                )
            )
        )
      )
      OR (
        d.disposition=6
        AND EXISTS (
          SELECT 1
          FROM provider_remote_terminal_settlements x
          WHERE x.dispatch_attempt_id=q.dispatch_attempt_id
            AND x.taskrun_id=q.taskrun_id AND x.taskrun_attempt_id=q.taskrun_attempt_id
            AND x.source_kind=2 AND x.terminal_status=t.disposition
            AND x.request_digest=q.request_digest
            AND x.response_id_digest=t.response_id_digest
            AND x.artifact_digest=t.plaintext_digest
            AND x.profile_digest=q.profile_digest
            AND x.pricing_revision_digest=q.pricing_revision_digest
            AND (
              (x.settlement_state=4 AND EXISTS (
                SELECT 1 FROM provider_terminal_outbox o
                WHERE o.dispatch_attempt_id=x.dispatch_attempt_id AND o.state=2
                  AND o.receipt_digest=x.application_receipt_digest
                  AND o.plaintext_digest=x.artifact_digest
              ))
              OR (x.settlement_state=3 AND (
                EXISTS (
                  SELECT 1
                  FROM taskrun_provider_cancel_fences c
                  JOIN provider_remote_artifact_cancel_closures z
                    ON z.dispatch_attempt_id=c.dispatch_attempt_id
                   AND z.cancellation_event_id=c.cancellation_event_id
                  WHERE c.dispatch_attempt_id=q.dispatch_attempt_id
                    AND c.taskrun_id=q.taskrun_id
                    AND c.taskrun_attempt_id=q.taskrun_attempt_id
                    AND z.artifact_digest=x.artifact_digest
                    AND z.terminal_status=x.terminal_status
                )
                OR EXISTS (
                  SELECT 1 FROM taskrun_unknown_successor_receipts u
                  WHERE u.predecessor_dispatch_attempt_id=q.dispatch_attempt_id
                    AND u.predecessor_taskrun_id=q.taskrun_id
                    AND u.predecessor_attempt_id=q.taskrun_attempt_id
                )
              ))
            )
            AND NOT EXISTS (
              SELECT 1 FROM taskrun_provider_cancel_fences c
              WHERE c.dispatch_attempt_id=q.dispatch_attempt_id
                AND c.taskrun_id=q.taskrun_id
                AND c.taskrun_attempt_id=q.taskrun_attempt_id
                AND NOT EXISTS (
                  SELECT 1 FROM provider_remote_artifact_cancel_closures z
                  WHERE z.dispatch_attempt_id=q.dispatch_attempt_id
                    AND z.taskrun_id=q.taskrun_id
                    AND z.taskrun_attempt_id=q.taskrun_attempt_id
                    AND z.artifact_digest=x.artifact_digest
                    AND z.terminal_status=x.terminal_status
                    AND z.cancellation_event_id=c.cancellation_event_id
                )
            )
        )
      )
      OR (
        d.disposition=4
        AND EXISTS (
          SELECT 1
          FROM provider_remote_terminal_settlements x
          WHERE x.dispatch_attempt_id=q.dispatch_attempt_id
            AND x.taskrun_id=q.taskrun_id
            AND x.taskrun_attempt_id=q.taskrun_attempt_id
            AND x.source_kind=2
            AND x.terminal_status=t.disposition
            AND x.request_digest=q.request_digest
            AND x.response_id_digest=t.response_id_digest
            AND x.artifact_digest=t.plaintext_digest
            AND x.profile_digest=q.profile_digest
            AND x.pricing_revision_digest=q.pricing_revision_digest
            AND (
              (x.settlement_state=4 AND EXISTS (
                SELECT 1 FROM provider_terminal_outbox o
                WHERE o.dispatch_attempt_id=x.dispatch_attempt_id AND o.state=2
                  AND o.receipt_digest=x.application_receipt_digest
                  AND o.plaintext_digest=x.artifact_digest
              ))
              OR (
                x.settlement_state=3
                AND (
                  EXISTS (
                    SELECT 1
                    FROM taskrun_provider_cancel_fences c
                    JOIN provider_remote_artifact_cancel_closures z
                      ON z.dispatch_attempt_id=c.dispatch_attempt_id
                     AND z.cancellation_event_id=c.cancellation_event_id
                    WHERE c.dispatch_attempt_id=q.dispatch_attempt_id
                      AND c.taskrun_id=q.taskrun_id AND c.taskrun_attempt_id=q.taskrun_attempt_id
                      AND z.artifact_digest=x.artifact_digest
                      AND z.terminal_status=x.terminal_status
                  )
                  OR EXISTS (
                    SELECT 1 FROM taskrun_unknown_successor_receipts u
                    WHERE u.predecessor_dispatch_attempt_id=q.dispatch_attempt_id
                      AND u.predecessor_taskrun_id=q.taskrun_id
                      AND u.predecessor_attempt_id=q.taskrun_attempt_id
                  )
                )
              )
            )
            AND NOT EXISTS (
              SELECT 1 FROM taskrun_provider_cancel_fences c
              WHERE c.dispatch_attempt_id=q.dispatch_attempt_id
                AND c.taskrun_id=q.taskrun_id AND c.taskrun_attempt_id=q.taskrun_attempt_id
                AND NOT EXISTS (
                  SELECT 1 FROM provider_remote_artifact_cancel_closures z
                  WHERE z.dispatch_attempt_id=q.dispatch_attempt_id
                    AND z.taskrun_id=q.taskrun_id
                    AND z.taskrun_attempt_id=q.taskrun_attempt_id
                    AND z.artifact_digest=x.artifact_digest
                    AND z.terminal_status=x.terminal_status
                    AND z.cancellation_event_id=c.cancellation_event_id
                )
            )
        )
      )
      OR EXISTS (
        SELECT 1
        FROM provider_remote_terminal_applications a
        JOIN provider_remote_terminal_settlements x USING(dispatch_attempt_id)
        WHERE a.dispatch_attempt_id=q.dispatch_attempt_id
          AND a.taskrun_id=q.taskrun_id
          AND a.taskrun_attempt_id=q.taskrun_attempt_id
          AND a.request_digest=q.request_digest
          AND a.response_id_digest=t.response_id_digest
          AND a.artifact_digest=t.plaintext_digest
          AND a.terminal_status=t.disposition
          AND x.source_kind=2
          AND x.settlement_state=3
          AND x.taskrun_id=a.taskrun_id
          AND x.taskrun_attempt_id=a.taskrun_attempt_id
          AND x.conversation_id=a.conversation_id
          AND x.generation_id=a.generation_id
          AND x.begin_command_id=a.begin_command_id
          AND x.request_digest=a.request_digest
          AND x.response_id_digest=a.response_id_digest
          AND x.artifact_digest=a.artifact_digest
          AND x.terminal_status=a.terminal_status
          AND x.publication_disposition=a.publication_disposition
          AND NOT EXISTS (
            SELECT 1
            FROM taskrun_provider_cancel_fences c
            WHERE c.dispatch_attempt_id=q.dispatch_attempt_id
              AND c.taskrun_id=q.taskrun_id
              AND c.taskrun_attempt_id=q.taskrun_attempt_id
              AND NOT EXISTS (
                SELECT 1
                FROM provider_remote_artifact_cancel_closures z
                WHERE z.dispatch_attempt_id=q.dispatch_attempt_id
                  AND z.taskrun_id=q.taskrun_id
                  AND z.taskrun_attempt_id=q.taskrun_attempt_id
                  AND z.conversation_id=x.conversation_id
                  AND z.artifact_digest=x.artifact_digest
                  AND z.terminal_status=x.terminal_status
                  AND z.cancellation_event_id=c.cancellation_event_id
              )
          )
      )
    )
)
"#;
