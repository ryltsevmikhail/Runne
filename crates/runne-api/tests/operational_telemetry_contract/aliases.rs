use std::collections::BTreeSet;

use super::{RuntimeOperationalTelemetrySnapshotV1, VALID_SNAPSHOT};

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

#[test]
fn generated_forbidden_alias_corpus_is_rejected_at_direct_and_nested_api_boundaries() {
    for (key, marker) in corpus() {
        for body in [
            std::str::from_utf8(VALID_SNAPSHOT).unwrap().replacen(
                "{",
                &format!("{{\"{key}\":\"{marker}\","),
                1,
            ),
            std::str::from_utf8(VALID_SNAPSHOT).unwrap().replacen(
                "\"tokens\":{",
                &format!("\"tokens\":{{\"{key}\":\"{marker}\","),
                1,
            ),
        ] {
            assert!(serde_json::from_str::<RuntimeOperationalTelemetrySnapshotV1>(&body).is_err());
        }
    }
}
