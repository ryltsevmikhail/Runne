#[test]
fn bounded_output_is_explicitly_truncated_with_blob_reference() {
    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    let result = gateway
        .close(ToolCloseRequest {
            invocation_id: "invocation-1".into(),
            request_digest: [1; 32],
            handle,
            evidence: ToolCloseEvidence {
                process_terminal: true,
                containment_released: true,
                cleanup_closed: true,
            },
            output: RawToolOutput {
                bytes: b"123456789".to_vec(),
                lines: vec!["first".into(), "second".into()],
                items: vec![serde_json::json!(1), serde_json::json!(2)],
                overflow_blob: Some(BlobRef::new("sha256:overflow").unwrap()),
            },
        })
        .unwrap();

    let ToolTerminalDisposition::Completed(output) = result else {
        panic!("expected completed output");
    };
    assert!(output.truncated());
    assert_eq!(output.bytes(), b"12345678");
    assert!(output.lines().is_empty());
    assert!(output.items().is_empty());
    assert_eq!(output.overflow_blob().unwrap().as_str(), "sha256:overflow");
}

#[test]
fn byte_bound_covers_structured_lines_and_items() {
    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    let result = gateway
        .close(ToolCloseRequest {
            invocation_id: "invocation-1".into(),
            request_digest: [1; 32],
            handle,
            evidence: ToolCloseEvidence {
                process_terminal: true,
                containment_released: true,
                cleanup_closed: true,
            },
            output: RawToolOutput {
                lines: vec!["a".repeat(64)],
                items: vec![serde_json::json!({"large": "b".repeat(64)})],
                overflow_blob: Some(BlobRef::new("sha256:structured-overflow").unwrap()),
                ..RawToolOutput::default()
            },
        })
        .unwrap();

    let ToolTerminalDisposition::Completed(output) = result else {
        panic!("expected completed output");
    };
    assert!(output.truncated());
    assert!(output.lines().is_empty());
    assert!(output.items().is_empty());
}

#[test]
fn missing_overflow_or_cleanup_evidence_is_uncertain() {
    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    let result = gateway
        .close(ToolCloseRequest {
            invocation_id: "invocation-1".into(),
            request_digest: [1; 32],
            handle,
            evidence: ToolCloseEvidence {
                process_terminal: true,
                containment_released: true,
                cleanup_closed: false,
            },
            output: RawToolOutput::default(),
        })
        .unwrap();
    assert_eq!(result, ToolTerminalDisposition::Uncertain);

    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    assert_eq!(
        gateway.close(ToolCloseRequest {
            invocation_id: "invocation-1".into(),
            request_digest: [1; 32],
            handle,
            evidence: ToolCloseEvidence {
                process_terminal: true,
                containment_released: true,
                cleanup_closed: true,
            },
            output: RawToolOutput {
                bytes: vec![0; 9],
                ..RawToolOutput::default()
            },
        }),
        Ok(ToolTerminalDisposition::Uncertain)
    );
}

#[test]
fn cancel_is_idempotent_and_does_not_close_execution() {
    let (gateway, _, _) = make_gateway(None);
    let handle = gateway.dispatch(request(1)).unwrap();
    let cancel = ToolCancelRequest {
        invocation_id: "invocation-1".into(),
        request_digest: [1; 32],
        handle,
    };
    assert_eq!(
        gateway.signal_cancel(cancel.clone()).unwrap(),
        ToolCancelDisposition::Signalled
    );
    assert_eq!(
        gateway.signal_cancel(cancel).unwrap(),
        ToolCancelDisposition::AlreadySignalled
    );
}
