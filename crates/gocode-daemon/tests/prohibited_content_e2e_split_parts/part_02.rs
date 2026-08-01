fn provider_request() -> ProviderCoordinatorRequest {
    ProviderCoordinatorRequest {
        call: ProviderCall::new(
            ProviderCallId::from_bytes([1; 16]),
            ModelRef::new(
                ProviderId::new("synthetic-provider").unwrap(),
                "synthetic-model",
                "2026-07-30",
            )
            .unwrap(),
            [2; 32],
            64,
            json!({"inert": MARKER}),
        )
        .unwrap(),
        authority_ref: ProviderEffectAuthorityRef::new([3; 16], 1).unwrap(),
        render_digest: [4; 32],
        profile_digest: [5; 32],
        attempt_id: DispatchAttemptId::from_bytes([6; 16]),
        permit_id: [7; 16],
        token_reservation_id: [8; 16],
        cost_reservation_id: [9; 16],
        fencing_token: 1,
        owner_id: "local-owner".into(),
        scope: "provider.dispatch".into(),
        provider_idempotency_key: "task-seven-provider".into(),
    }
}
