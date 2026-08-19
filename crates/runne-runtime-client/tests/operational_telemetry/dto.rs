use runne_runtime_client::RuntimeApiErrorKind;

use crate::support::*;

#[tokio::test]
async fn telemetry_rejects_nested_unknown_schema_and_enum_wire() {
    let valid = valid_snapshot(1);
    let cases = [
        (
            "root unknown",
            valid.replacen(
                "\"recoveryTransient\"",
                "\"forbidden\":0,\"recoveryTransient\"",
                1,
            ),
        ),
        (
            "nested unknown",
            valid.replacen("\"tokens\":{", "\"tokens\":{\"forbidden\":0,", 1),
        ),
        (
            "schema",
            valid.replacen("\"schemaVersion\":1", "\"schemaVersion\":2", 1),
        ),
        (
            "freshness enum",
            valid.replacen(
                "\"freshness\":\"observed_in_current_cycle\"",
                "\"freshness\":\"unknown\"",
                1,
            ),
        ),
        (
            "completeness enum",
            valid.replacen(
                "\"completeness\":\"complete\"",
                "\"completeness\":\"unknown\"",
                1,
            ),
        ),
        (
            "status enum",
            valid.replacen(
                "\"status\":\"lower_bound_since_launch\"",
                "\"status\":\"unknown\"",
                1,
            ),
        ),
        (
            "zero generation",
            valid.replacen("\"launchGeneration\":1", "\"launchGeneration\":0", 1),
        ),
        (
            "meta combination",
            valid.replacen(
                "\"freshness\":\"observed_in_current_cycle\"",
                "\"freshness\":\"unavailable\"",
                1,
            ),
        ),
    ];
    for (name, body) in cases {
        let (client, request) = client_for(response(200, &[], body), true, 1).await;
        let result = client.operational_telemetry().await;
        assert!(result.is_err(), "accepted invalid case: {name}");
        assert_static_error(
            &telemetry_error(result),
            RuntimeApiErrorKind::InvalidResponse,
        );
        request.await.expect(name);
    }
}

#[tokio::test]
async fn telemetry_rejects_durable_and_budget_invariant_wire() {
    let valid = valid_snapshot(1);
    let cases = [
        (
            "durable partial presence",
            valid.replacen("\"uncertainAttempts\":0", "\"uncertainAttempts\":null", 1),
        ),
        (
            "durable wrong completeness",
            valid.replacen(
                "\"completeness\":\"complete\"",
                "\"completeness\":\"partial\"",
                1,
            ),
        ),
        (
            "durable unavailable completeness",
            valid.replacen(
                "\"completeness\":\"complete\"",
                "\"completeness\":\"unavailable\"",
                1,
            ),
        ),
        (
            "budget relation",
            valid.replacen("\"remaining\":5", "\"remaining\":4", 1),
        ),
        (
            "expiry relation",
            valid.replacen(
                "\"nearestUnexpiredExpiryUnixSeconds\":11",
                "\"nearestUnexpiredExpiryUnixSeconds\":10",
                1,
            ),
        ),
        (
            "lower missing count",
            valid.replacen(
                "\"observedOutboxRecoveriesInGeneration\":0",
                "\"observedOutboxRecoveriesInGeneration\":null",
                1,
            ),
        ),
        (
            "lower dropped",
            valid.replacen("\"droppedEventCount\":0", "\"droppedEventCount\":1", 1),
        ),
    ];
    for (name, body) in cases {
        let (client, request) = client_for(response(200, &[], body), true, 1).await;
        let result = client.operational_telemetry().await;
        assert!(result.is_err(), "accepted invalid case: {name}");
        assert_static_error(
            &telemetry_error(result),
            RuntimeApiErrorKind::InvalidResponse,
        );
        request.await.expect(name);
    }
}

#[tokio::test]
async fn telemetry_rejects_truncation_and_saturation_invariant_wire() {
    let valid = valid_snapshot(1);
    let cases = [
        (
            "truncated missing count",
            valid
                .replacen(
                    "\"status\":\"lower_bound_since_launch\"",
                    "\"status\":\"truncated_lower_bound_since_launch\"",
                    1,
                )
                .replacen(
                    "\"observedOutboxRecoveriesInGeneration\":0",
                    "\"observedOutboxRecoveriesInGeneration\":null",
                    1,
                ),
        ),
        (
            "truncated zero drop",
            valid.replacen(
                "\"status\":\"lower_bound_since_launch\"",
                "\"status\":\"truncated_lower_bound_since_launch\"",
                1,
            ),
        ),
        (
            "unavailable status meta",
            valid.replacen(
                "\"status\":\"lower_bound_since_launch\"",
                "\"status\":\"unavailable\"",
                1,
            ),
        ),
        (
            "unavailable observed count",
            valid
                .replacen(
                    "\"status\":\"lower_bound_since_launch\"",
                    "\"status\":\"unavailable\"",
                    1,
                )
                .replacen(
                    "\"freshness\":\"observed_in_current_cycle\"",
                    "\"freshness\":\"unavailable\"",
                    2,
                )
                .replacen(
                    "\"completeness\":\"complete\"",
                    "\"completeness\":\"unavailable\"",
                    2,
                ),
        ),
        (
            "saturation mismatch",
            valid.replacen("\"counterSaturated\":false", "\"counterSaturated\":true", 1),
        ),
        (
            "saturation missing",
            valid.replacen(
                "\"droppedEventCount\":0",
                "\"droppedEventCount\":18446744073709551615",
                1,
            ),
        ),
    ];
    for (name, body) in cases {
        let (client, request) = client_for(response(200, &[], body), true, 1).await;
        let result = client.operational_telemetry().await;
        assert!(result.is_err(), "accepted invalid case: {name}");
        assert_static_error(
            &telemetry_error(result),
            RuntimeApiErrorKind::InvalidResponse,
        );
        request.await.expect(name);
    }
    let (client, request) = client_for(response(200, &[], valid_snapshot(2)), true, 1).await;
    assert_static_error(
        &telemetry_error(client.operational_telemetry().await),
        RuntimeApiErrorKind::InvalidResponse,
    );
    request.await.expect("generation mismatch");
}
