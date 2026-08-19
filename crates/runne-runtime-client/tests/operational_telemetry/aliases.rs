use std::collections::BTreeSet;

use runne_runtime_client::RuntimeApiErrorKind;

use crate::support::*;

fn corpus() -> Vec<(String, &'static str)> {
    let categories: &[(&[&str], &str)] = &[
        (&["authorization"], "task3-authorization-marker"),
        (&["credential"], "task3-credential-marker"),
        (&["token"], "task3-api-token-marker"),
        (&["api", "token"], "task3-api-token-marker"),
        (&["prompt"], "task3-prompt-marker"),
        (&["output"], "task3-output-marker"),
        (&["body"], "task3-provider-body-marker"),
        (&["provider", "body"], "task3-provider-body-marker"),
        (&["sse"], "task3-sse-marker"),
        (&["chunk"], "task3-sse-marker"),
        (&["error"], "task3-raw-error-marker"),
        (&["raw", "error"], "task3-raw-error-marker"),
        (&["exception"], "task3-raw-error-marker"),
        (&["path"], "task3-path-marker"),
        (&["secret", "path"], "task3-path-marker"),
        (&["endpoint"], "task3-path-marker"),
        (&["url"], "task3-path-marker"),
        (&["headers"], "task3-authorization-marker"),
        (&["request", "headers"], "task3-authorization-marker"),
    ];
    categories
        .iter()
        .flat_map(|(words, marker)| forms(words).into_iter().map(|key| (key, *marker)))
        .collect()
}

fn forms(words: &[&str]) -> BTreeSet<String> {
    let compact = words.concat();
    let title = |word: &str| format!("{}{}", word[..1].to_uppercase(), &word[1..]);
    let camel = format!(
        "{}{}",
        words[0],
        words[1..]
            .iter()
            .map(|word| title(word))
            .collect::<String>()
    );
    let pascal = words.iter().map(|word| title(word)).collect::<String>();
    [
        compact.clone(),
        compact.to_uppercase(),
        camel,
        pascal,
        words.join("_"),
        words.join("-"),
        words.join("."),
        words.join(" "),
    ]
    .into_iter()
    .collect()
}

#[tokio::test]
async fn generated_forbidden_alias_corpus_is_rejected_at_direct_and_nested_client_boundaries() {
    for (key, marker) in corpus() {
        for body in [
            valid_snapshot(1).replacen('{', &format!(r#"{{"{key}":"{marker}","#), 1),
            valid_snapshot(1).replacen(
                r#""tokens":{"#,
                &format!(r#""tokens":{{"{key}":"{marker}","#),
                1,
            ),
        ] {
            let (client, request) = client_for(response(200, &[], body), true, 1).await;
            let error = telemetry_error(client.operational_telemetry().await);
            assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
            assert!(!format!("{error:?}").contains(marker));
            assert!(!error.to_string().contains(marker));
            request.await.unwrap();
        }
    }
}
