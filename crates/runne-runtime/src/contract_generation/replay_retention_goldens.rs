fn replay_retention_baseline_golden() -> Value {
    json!({
        "code": "replay_retention_gap",
        "requestId": "018f2e3a-7000-7000-8000-000000000120",
        "baseline": {
            "schemaVersion": 1, "authorityId": "018f2e3a700070008000000000000101",
            "principalId": "local-owner", "lineageId": "018f2e3a700070008000000000000102",
            "runtimeSessionBindingDigest": "03".repeat(32), "replayScopeDigest": "04".repeat(32),
            "aggregateKind": "conversation", "aggregateId": "018f2e3a700070008000000000000110",
            "sequence": 1, "version": 1, "baselineGlobalPosition": 1, "projectionCodec": 1,
            "projectionBytes": "AQGPLjpwAHAAgAAAAAAAARABjy46cABwAIAAAAAAAAERAQAAAAAA",
            "projectionDigest": "48668e97acdc9c689c0b74d0affd5e090e8a1d327ac3ccf08c94fa6288ef32ed",
            "retainedFloor": 2, "capturedHighWater": 2, "retentionGeneration": 1,
            "retentionWitness": "06".repeat(32), "issuedAtUnixMs": 1_722_330_000_000_u64,
            "expiresAtUnixMs": 1_722_330_030_000_u64, "witnessMac": "07".repeat(32),
        },
    })
}

fn replay_retention_baseline_v2_golden() -> Value {
    json!({
        "code": "replay_retention_gap",
        "requestId": "018f2e3a-7000-7000-8000-000000000120",
        "baseline": {
            "schemaVersion": 2, "authorityId": "018f2e3a700070008000000000000101",
            "principalId": "local-owner", "lineageId": "018f2e3a700070008000000000000102",
            "runtimeSessionBindingDigest": "03".repeat(32), "replayScopeDigest": "04".repeat(32),
            "aggregateKind": "conversation", "aggregateId": "018f2e3a700070008000000000000110",
            "sequence": 1, "version": 1, "baselineGlobalPosition": 1,
            "headEventId": "018f2e3a700070008000000000000112",
            "headIntegrityDigest": "05".repeat(32), "promotionCodec": 1,
            "promotionProjectionBytes": "AQGPLjpwAHAAgAAAAAAAARABjy46cABwAIAAAAAAAAERAQAAAAAA",
            "promotionProjectionDigest": "48668e97acdc9c689c0b74d0affd5e090e8a1d327ac3ccf08c94fa6288ef32ed",
            "retainedFloor": 2, "capturedHighWater": 2, "retentionGeneration": 1,
            "retentionManifestDigest": "06".repeat(32), "issuedAtUnixMs": 1_722_330_000_000_u64,
            "expiresAtUnixMs": 1_722_330_030_000_u64, "witnessMac": "07".repeat(32),
        },
    })
}

fn replay_resume_from_baseline_golden() -> Value {
    let baseline = replay_retention_baseline_v2_golden()["baseline"].clone();
    json!({
        "request": {"baseline": baseline},
        "acceptedResponse": {
            "requestId": "018f2e3a-7000-7000-8000-000000000120",
            "sessionId": "018f2e3a700070008000000000000118",
            "highWaterRef": "runne-replay-cursor-v1.7b7d",
            "baselineCheckpoint": "runne-replay-cursor-v1.7b7d",
            "acceptedPromotion": {
                "codec": 1,
                "projectionBytes": "AQGPLjpwAHAAgAAAAAAAARABjy46cABwAIAAAAAAAAERAQAAAAAA",
                "projectionDigest": "48668e97acdc9c689c0b74d0affd5e090e8a1d327ac3ccf08c94fa6288ef32ed",
                "sequence": 1, "version": 1, "globalPosition": 1,
                "headEventId": "018f2e3a700070008000000000000112",
                "headIntegrityDigest": "05".repeat(32), "capturedHighWater": 2,
            },
            "events": [], "hasMore": false,
        },
    })
}
