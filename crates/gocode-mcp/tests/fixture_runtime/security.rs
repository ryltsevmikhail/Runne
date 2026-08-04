#[test]
fn initialize_rejects_changed_authenticated_tuple_members() {
    let mut fixture = runtime();
    initialize(&mut fixture);
    let request = |runtime, session, connection, generation, server, profile, protocol| {
        FixtureInitialize::new(
            McpRuntimeInstanceId::new(runtime).unwrap(),
            McpSessionId::new(session).unwrap(),
            McpConnectionId::new(connection).unwrap(),
            generation,
            server,
            "1.0.0",
            profile,
            protocol,
        )
    };
    assert_eq!(
        fixture.initialize(request(
            "runtime-1",
            "session-1",
            "connection-1",
            1,
            "fixture-server",
            "fixture-v1",
            "wrong"
        )),
        Err(FixtureMcpFailure::ProtocolVersionUnsupported)
    );
    assert_eq!(
        fixture.initialize(request(
            "runtime-1",
            "session-1",
            "connection-1",
            1,
            "wrong",
            "fixture-v1",
            "2025-11-25"
        )),
        Err(FixtureMcpFailure::ServerIdentityMismatch)
    );
    assert_eq!(
        fixture.initialize(request(
            "runtime-2",
            "session-1",
            "connection-1",
            1,
            "fixture-server",
            "fixture-v1",
            "2025-11-25"
        )),
        Err(FixtureMcpFailure::ServerIdentityMismatch)
    );
    assert_eq!(
        fixture.initialize(request(
            "runtime-1",
            "session-2",
            "connection-1",
            1,
            "fixture-server",
            "fixture-v1",
            "2025-11-25"
        )),
        Err(FixtureMcpFailure::SessionMismatch)
    );
    assert_eq!(
        fixture.initialize(request(
            "runtime-1",
            "session-1",
            "connection-2",
            1,
            "fixture-server",
            "fixture-v1",
            "2025-11-25"
        )),
        Err(FixtureMcpFailure::ConnectionMismatch)
    );
    assert_eq!(
        fixture.initialize(request(
            "runtime-1",
            "session-1",
            "connection-1",
            2,
            "fixture-server",
            "fixture-v1",
            "2025-11-25"
        )),
        Err(FixtureMcpFailure::GenerationMismatch)
    );
}

#[test]
fn errors_and_audit_redact_secret_markers_and_fixture_source_has_no_backend() {
    let markers = [
        "SENTINEL_CREDENTIAL",
        "SENTINEL_AUTHORIZATION",
        "SENTINEL_PROMPT",
        "SENTINEL_OUTPUT",
        "SENTINEL_PATH",
        "SENTINEL_RAW_ERROR",
    ];
    let mut fixture = runtime();
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();
    for (index, key) in ["credential", "Authorization", "prompt", "output", "path"]
        .iter()
        .enumerate()
    {
        let error = publication
            .issue_dispatch(
                "read",
                &format!("secret-{index}"),
                json!({*key: markers[index]}),
                "p",
                "a",
                1,
            )
            .unwrap_err();
        assert!(
            markers
                .iter()
                .all(|marker| !format!("{error:?} {error}").contains(marker))
        );
    }
    assert!(
        markers
            .iter()
            .all(|marker| !format!("{:?}", fixture.audit()).contains(marker))
    );
    let sources = [
        include_str!("../../src/fixture.rs"),
        include_str!("../../src/fixture/mode.rs"),
        include_str!("../../src/fixture/model.rs"),
        include_str!("../../src/fixture/model/identity.rs"),
        include_str!("../../src/fixture/model/tool.rs"),
        include_str!("../../src/fixture/model/script.rs"),
        include_str!("../../src/fixture/model/limits.rs"),
        include_str!("../../src/fixture/model/helpers.rs"),
        include_str!("../../src/fixture/runtime.rs"),
        include_str!("../../src/fixture/runtime/lifecycle.rs"),
        include_str!("../../src/fixture/runtime/dispatch.rs"),
        include_str!("../../src/fixture/publication.rs"),
        include_str!("../../src/fixture/schema.rs"),
        include_str!("../../src/fixture/schema/definition.rs"),
        include_str!("../../src/fixture/schema/value.rs"),
        include_str!("../../src/fixture/transport.rs"),
        include_str!("../../src/fixture/debug.rs"),
    ];
    assert_eq!(sources.len(), 17);
    for forbidden in [
        "std::net",
        "Tcp",
        "Udp",
        "UnixStream",
        "std::process",
        "Command",
        "tokio",
        "reqwest",
        "WebSocket",
        "Sse",
        "Stdio",
        "std::fs",
        "File",
        "OpenOptions",
        "std::env",
        "env::var",
        "std::path",
        "fs::",
        "Path::",
        "PathBuf",
        "current_dir",
        "read_dir",
        "read_to_string",
        "set_current_dir",
        "set_var",
        "var_os",
        "PATH",
        "renderer",
    ] {
        assert!(sources.iter().all(|source| !source.contains(forbidden)), "{forbidden}");
    }
}

#[test]
fn public_fixture_debug_is_metadata_only() {
    let mut fixture = runtime();
    initialize(&mut fixture);
    let publication = fixture.discover().unwrap();
    let capability = publication.issue_dispatch(
        "read",
        "debug-marker",
        json!({"name":"SENTINEL_OUTPUT"}),
        "p",
        "a",
        1,
    );
    assert!(capability.is_err());
    let mut completed = publication
        .issue_dispatch("read", "debug-completed", json!({"name":"ok"}), "p", "a", 1)
        .unwrap();
    assert_eq!(fixture.dispatch(&mut completed, None), Ok(FixtureCallResult::Completed));
    for marker in [
        "FixtureMcpRuntime",
        "FixturePublication",
        "FixtureAuditRecord",
    ] {
        let rendered = if marker == "FixtureMcpRuntime" {
            format!("{fixture:?}")
        } else if marker == "FixturePublication" {
            format!("{publication:?}")
        } else {
            format!("{:?}", fixture.audit())
        };
        assert!(rendered.contains(marker));
        assert!(!rendered.contains("SENTINEL_OUTPUT"));
    }
}
