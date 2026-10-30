use super::*;

fn validated_effects(publication: &str, accounting: &str) -> runne_app_core::TaskRunEffectsV1 {
    let not_applicable = publication == "not_applicable";
    runne_app_core::test_decode_task_run_effects_wire(serde_json::json!({
        "taskRunId": "018f0000-0000-7000-8000-000000000001",
        "streamVersion": 9,
        "attemptId": if not_applicable { serde_json::Value::Null } else {
            serde_json::json!("018f0000-0000-7000-8000-000000000002")
        },
        "cancellationRequested": !not_applicable,
        "localCommand": null,
        "remote": {
            "outcome": if not_applicable { "not_applicable" } else { "completed" },
            "publication": publication,
            "accounting": accounting,
            "cancellation": if not_applicable { "not_requested" } else { "requested" },
            "availability": if not_applicable { "not_configured" } else { "unknown" },
            "capabilities": {
                "statusCheck": !not_applicable,
                "streamResume": false,
                "remoteCancel": !not_applicable
            },
            "usageKnown": if not_applicable { serde_json::Value::Null } else { serde_json::json!(true) }
        },
        "successor": if not_applicable { "not_applicable" } else { "requires_duplicate_effect_acknowledgment" }
    }))
    .expect("fixture passes the production closed effects parser")
}

#[test]
fn actual_effects_conversion_serializes_all_publication_and_accounting_variants() {
    let variants = [
        ("not_applicable", "not_applicable"),
        ("unknown", "unknown"),
        ("unknown", "known"),
        ("allowed", "unknown"),
        ("allowed", "known"),
        ("withheld", "unknown"),
        ("withheld", "known"),
    ];

    for (publication, accounting) in variants {
        let not_applicable = publication == "not_applicable";
        let typed = validated_effects(publication, accounting);
        let serialized = serde_json::to_value(task_run_effects_to_wire(&typed))
            .expect("serializable IPC response");
        let expected = serde_json::json!({
            "taskRunId": "018f0000-0000-7000-8000-000000000001",
            "streamVersion": 9,
            "attemptId": if not_applicable { serde_json::Value::Null } else {
                serde_json::json!("018f0000-0000-7000-8000-000000000002")
            },
            "cancellationRequested": !not_applicable,
            "localCommand": null,
            "remote": {
                "outcome": if not_applicable { "not_applicable" } else { "completed" },
                "publication": publication,
                "accounting": accounting,
                "cancellation": if not_applicable { "not_requested" } else { "requested" },
                "availability": if not_applicable { "not_configured" } else { "unknown" },
                "capabilities": {
                    "statusCheck": !not_applicable,
                    "streamResume": false,
                    "remoteCancel": !not_applicable
                },
                "usageKnown": if not_applicable { serde_json::Value::Null } else {
                    serde_json::json!(true)
                }
            },
            "successor": if not_applicable { "not_applicable" } else {
                "requires_duplicate_effect_acknowledgment"
            }
        });
        assert_eq!(serialized, expected);
    }
}

#[test]
fn already_terminal_cancellation_serializes_without_claiming_provider_cancelled() {
    let typed = validated_effects("withheld", "known");
    let mut value = serde_json::to_value(task_run_effects_to_wire(&typed)).unwrap();
    value["remote"]["cancellation"] = serde_json::json!("already_terminal");
    let typed = runne_app_core::test_decode_task_run_effects_wire(value).unwrap();
    let serialized = serde_json::to_value(task_run_effects_to_wire(&typed)).unwrap();
    assert_eq!(serialized["remote"]["cancellation"], "already_terminal");
    assert_eq!(serialized["remote"]["outcome"], "completed");
}
