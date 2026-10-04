fn online_claim(
    database: &ArmedProviderTestDatabase,
    request: &ProviderAuthorityIssueRequest,
    call_byte: u8,
) -> ProviderDispatchClaim {
    let call = online_call(request);
    online_stream_fixture::start_bound(
        &database.database,
        &database.execution,
        &database.launch.borrow(),
        call,
        request,
        runne_provider::ProviderStreamId::from_bytes([call_byte.wrapping_add(40); 16]),
        call_byte,
    )
    .1
}

fn online_pending_claim(
    database: &ArmedProviderTestDatabase,
    request: &ProviderAuthorityIssueRequest,
    call_byte: u8,
) -> ProviderDispatchClaim {
    online_stream_fixture::start_pending_bound(
        &database.database,
        &database.execution,
        &database.launch.borrow(),
        online_call(request),
        request,
        call_byte,
    )
}

fn online_call(request: &ProviderAuthorityIssueRequest) -> ProviderCall {
    ProviderCall::new(
        request.prepared.call_id,
        ModelRef::new(request.provider_id.clone(), "fixture-model", "2026-08-06").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap()
}
