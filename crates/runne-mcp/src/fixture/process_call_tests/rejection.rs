use super::support::*;

#[test]
fn typed_issuance_rejects_stale_publication_binding() {
    let mut runtime = runtime();
    initialize(&mut runtime);
    let publication = runtime.discover().unwrap();
    let (authority, intent) = authority_and_intent(&publication.binding, "invocation-1");
    runtime
        .reconnect(McpConnectionId::new("connection-2").unwrap())
        .unwrap();

    assert!(matches!(
        publication.issue_process_dispatch_for_test(
            "process",
            "invocation-1",
            json!({}),
            intent,
            &authority,
            20,
            10
        ),
        Err(FixtureMcpFailure::DiscoveryStale)
    ));
}

#[test]
fn c2b_rejects_an_intent_that_differs_from_the_typed_capability() {
    let mut runtime = runtime();
    initialize(&mut runtime);
    let publication = runtime.discover().unwrap();
    let (authority, intent) = authority_and_intent(&publication.binding, "invocation-1");
    let capability = publication
        .published
        .issue_process_dispatch(
            &publication.binding,
            publication
                .published
                .snapshot()
                .tool_refs()
                .first()
                .unwrap(),
            McpInvocationId::new("invocation-1").unwrap(),
            json!({}),
            &intent,
        )
        .unwrap();
    let (_, different_intent) = authority_and_intent(&publication.binding, "invocation-2");

    assert!(matches!(
        capability.verify_c2b(&different_intent),
        Err(crate::discovery::ProcessCallBindingError::ProcessIntentMismatch)
    ));
    let _ = authority.issue_capability(&intent, 20).unwrap();
}
