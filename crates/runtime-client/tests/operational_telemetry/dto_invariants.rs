use gocode_runtime_client::RuntimeApiErrorKind;

use crate::support::*;

#[tokio::test]
async fn telemetry_rejects_each_remaining_task2_constructor_branch() {
    let lower = valid_snapshot(1);
    let truncated = valid_truncated();
    let cases = [
        (
            "budget reserved plus settled exceeds limit",
            lower.replacen("\"limit\":10,\"reserved\":2,\"settled\":3,\"remaining\":5", "\"limit\":4,\"reserved\":2,\"settled\":3,\"remaining\":0", 1),
        ),
        (
            "budget checked add overflow",
            lower.replacen("\"limit\":10,\"reserved\":2,\"settled\":3,\"remaining\":5", "\"limit\":18446744073709551615,\"reserved\":18446744073709551615,\"settled\":1,\"remaining\":0", 1),
        ),
        (
            "expiry expired count exceeds active count",
            lower.replacen("\"activeCount\":1,\"expiredActiveCount\":0", "\"activeCount\":0,\"expiredActiveCount\":1", 1),
        ),
        ("lower partial meta", recovery_meta(&lower, "observed_in_current_cycle", "partial")),
        ("lower unavailable meta", recovery_meta(&lower, "unavailable", "unavailable")),
        ("lower dropped count", lower.replacen("\"droppedEventCount\":0", "\"droppedEventCount\":1", 1)),
        ("lower saturated", lower.replacen("\"counterSaturated\":false", "\"counterSaturated\":true", 1)),
        ("truncated complete meta", recovery_meta(&truncated, "observed_in_current_cycle", "complete")),
        ("truncated unavailable meta", recovery_meta(&truncated, "unavailable", "unavailable")),
        ("truncated zero drop", truncated.replacen("\"droppedEventCount\":1", "\"droppedEventCount\":0", 1)),
        ("truncated missing count", truncated.replacen("\"observedOutboxRecoveriesInGeneration\":0", "\"observedOutboxRecoveriesInGeneration\":null", 1)),
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
async fn telemetry_accepts_empty_durable_only_with_unavailable_meta() {
    let (client, request) = client_for(
        response(
            200,
            &[],
            empty_durable_snapshot("unavailable", "unavailable"),
        ),
        true,
        1,
    )
    .await;
    assert!(
        client
            .operational_telemetry()
            .await
            .expect("unavailable durable telemetry")
            .durable()
            .accounting()
            .is_none()
    );
    request.await.expect("valid unavailable durable");

    for (name, freshness, completeness) in [
        (
            "complete empty durable",
            "observed_in_current_cycle",
            "complete",
        ),
        (
            "partial empty durable",
            "observed_in_current_cycle",
            "partial",
        ),
    ] {
        let (client, request) = client_for(
            response(200, &[], empty_durable_snapshot(freshness, completeness)),
            true,
            1,
        )
        .await;
        assert_static_error(
            &telemetry_error(client.operational_telemetry().await),
            RuntimeApiErrorKind::InvalidResponse,
        );
        request.await.expect(name);
    }
}

fn valid_truncated() -> String {
    let body = valid_snapshot(1);
    let body = recovery_meta(&body, "observed_in_current_cycle", "partial");
    body.replacen(
        "\"status\":\"lower_bound_since_launch\",\"observedOutboxRecoveriesInGeneration\":0,\"droppedEventCount\":0",
        "\"status\":\"truncated_lower_bound_since_launch\",\"observedOutboxRecoveriesInGeneration\":0,\"droppedEventCount\":1",
        1,
    )
}

fn recovery_meta(body: &str, freshness: &str, completeness: &str) -> String {
    let current = if body.contains("\"recoveryTransient\":{\"meta\":{\"observedAtUnixSeconds\":10,\"freshness\":\"observed_in_current_cycle\",\"completeness\":\"partial\"}") {
        "partial"
    } else {
        "complete"
    };
    body.replacen(
        &format!("\"recoveryTransient\":{{\"meta\":{{\"observedAtUnixSeconds\":10,\"freshness\":\"observed_in_current_cycle\",\"completeness\":\"{current}\"}}"),
        &format!("\"recoveryTransient\":{{\"meta\":{{\"observedAtUnixSeconds\":10,\"freshness\":\"{freshness}\",\"completeness\":\"{completeness}\"}}"),
        1,
    )
}

fn empty_durable_snapshot(freshness: &str, completeness: &str) -> String {
    format!(
        "{{\"schemaVersion\":1,\"observedAtUnixSeconds\":10,\"launchGeneration\":1,\"durable\":{{\"meta\":{{\"observedAtUnixSeconds\":10,\"freshness\":\"{freshness}\",\"completeness\":\"{completeness}\"}},\"accounting\":null,\"providerEffectAuthorities\":null,\"providerApprovalLease\":null,\"committedProviderEffects\":null,\"uncertainAttempts\":null}},\"recoveryTransient\":{{\"meta\":{{\"observedAtUnixSeconds\":10,\"freshness\":\"observed_in_current_cycle\",\"completeness\":\"complete\"}},\"status\":\"lower_bound_since_launch\",\"observedOutboxRecoveriesInGeneration\":0,\"droppedEventCount\":0,\"counterSaturated\":false}}}}"
    )
}
