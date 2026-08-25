#[test]
fn approval_wire_requires_exact_bounded_binding() {
    let value = serde_json::from_str::<ApprovalWire>(
        r#"{"approvalId":"018f2e3a-7000-7000-8000-000000000212","taskRunId":"018f2e3a-7000-7000-8000-000000000212","attemptId":null,"invocationId":"018f2e3a-7000-7000-8000-000000000212","action":"fs:write","resource":"workspace:/src/main.rs","actionDigest":"1111111111111111111111111111111111111111111111111111111111111111","policyRevision":7,"requestVersion":3,"expiresAt":2000,"riskSummary":"write source","state":"pending"}"#,
    )
    .expect("valid approval wire");
    let summary = ApprovalSummaryDto::try_from(value).expect("valid approval projection");
    assert!(summary.requires_decision());
    assert_eq!(summary.action_digest(), &[0x11; 32]);
}

#[test]
fn approval_wire_rejects_uppercase_digest_and_unknown_fields() {
    let uppercase = r#"{"approvalId":"018f2e3a-7000-7000-8000-000000000212","taskRunId":"018f2e3a-7000-7000-8000-000000000212","attemptId":null,"invocationId":"018f2e3a-7000-7000-8000-000000000212","action":"fs:write","resource":"workspace:/src/main.rs","actionDigest":"111111111111111111111111111111111111111111111111111111111111111A","policyRevision":7,"requestVersion":3,"expiresAt":2000,"riskSummary":"write source","state":"pending"}"#;
    assert!(ApprovalSummaryDto::try_from(serde_json::from_str::<ApprovalWire>(uppercase).unwrap()).is_err());
    assert!(serde_json::from_str::<ApprovalWire>(
        r#"{"approvalId":"018f2e3a-7000-7000-8000-000000000212","taskRunId":"018f2e3a-7000-7000-8000-000000000212","attemptId":null,"invocationId":"018f2e3a-7000-7000-8000-000000000212","action":"fs:write","resource":"workspace:/src/main.rs","actionDigest":"1111111111111111111111111111111111111111111111111111111111111111","policyRevision":7,"requestVersion":3,"expiresAt":2000,"riskSummary":"write source","state":"pending","extra":true}"#,
    ).is_err());
}

#[test]
fn approval_ack_rejects_pending_state() {
    let wire = ApprovalAcknowledgementWire {
        approval_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000212").unwrap(),
        task_run_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000212").unwrap(),
        new_version: 4,
        state: ApprovalStateWire::Pending,
    };
    assert!(ApprovalDecisionAcknowledgementDto::try_from(wire).is_err());
}
