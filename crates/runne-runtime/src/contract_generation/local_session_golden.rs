fn local_session_golden() -> Value {
    json!({
        "authenticateRequest": {
            "authority": "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo",
            "challengeId": "AQEBAQEBAQEBAQEBAQEBAQ",
            "finalProof": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "keyVersion": 1,
            "wireVersion": "3",
        },
        "authenticateResponse": {
            "expiresAtMonotonicMillis": 600000,
            "keyVersion": 1,
            "sessionId": "018f2e3a700070008000000000000112",
            "wireVersion": "3",
        },
        "challengeRequest": {
            "clientNonce": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
            "expiry": "2025-01-01T00:00:30.000000Z",
            "keyVersion": 1,
            "notBefore": "2025-01-01T00:00:00.000000Z",
            "preallocationProof": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "wireVersion": "3",
        },
        "challengeResponse": {
            "challengeId": "AQEBAQEBAQEBAQEBAQEBAQ",
            "keyVersion": 1,
            "serverNonce": "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
            "wireVersion": "3",
        },
    })
}
