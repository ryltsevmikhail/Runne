    fn test_live_session() -> ReplayLiveSession {
        test_live_session_with_client(test_client("127.0.0.1:9".parse().unwrap()))
    }

    fn test_live_session_with_client(client: AuthenticatedRuntimeClient) -> ReplayLiveSession {
        let scope = ReplayScope::new(
            ReplayAggregateKind::Conversation,
            CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
        );
        ReplayLiveSession {
            client,
            scope,
            session_id: session(),
            live_delivery_id: wire::live_id("018f2e3a-7000-7000-8000-000000000117").unwrap(),
            validator: DeliveryValidator::new(scope, ReplayIdentityTracker::new()),
            response: None,
            decoder: SseDecoder::default(),
            pending: VecDeque::new(),
            last_delivery_sequence: None,
            terminal_returned: false,
            unacknowledged: None,
        }
    }

    fn live_delivery_fixture(delivery_sequence: u64) -> serde_json::Value {
        let mut canonical_event = fixture();
        canonical_event.as_object_mut().unwrap().remove("cursor");
        serde_json::json!({
            "transportVersion": 1,
            "replaySessionId": "018f2e3a700070008000000000000118",
            "liveDeliveryId": "018f2e3a-7000-7000-8000-000000000117",
            "deliverySequence": delivery_sequence,
            "canonicalEvent": canonical_event,
            "replayCursor": "runne-replay-cursor-v1.7b7d"
        })
    }

    fn test_client(address: std::net::SocketAddr) -> AuthenticatedRuntimeClient {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        AuthenticatedRuntimeClient::from_local_session(
            client,
            format!("http://{address}"),
            crate::RuntimeSessionAuthority::from_local_session([7; 32]),
            crate::RuntimeSessionInfo {
                profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
                schema_hash: crate::GOLDEN_BUNDLE_HASH.to_owned(),
                runtime_version: "test".to_owned(),
                capabilities: crate::REQUIRED_RUNTIME_CAPABILITIES
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                authority_id: "authority".to_owned(),
                principal_id: "local-owner".to_owned(),
                event_log_lineage_id: "lineage".to_owned(),
                daemon_instance_id: "instance".to_owned(),
                launch_generation: 1,
                session_id: "session".to_owned(),
                authorization_epoch: 0,
                sensitivity_ceiling: "sensitive".to_owned(),
                certificate_sha256: "certificate".to_owned(),
                capability_digest: "capabilities".to_owned(),
            },
        )
    }

    async fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&chunk[..read]);
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("content-length: ")
                    .or_else(|| line.strip_prefix("Content-Length: "))
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0);
            request.extend_from_slice(&chunk[..read]);
        }
        let path = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap()
            .to_owned();
        (
            path,
            request[header_end..header_end + content_length].to_vec(),
        )
    }

    async fn write_json(stream: &mut TcpStream, value: &serde_json::Value) {
        let body = serde_json::to_vec(value).unwrap();
        let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
    }
