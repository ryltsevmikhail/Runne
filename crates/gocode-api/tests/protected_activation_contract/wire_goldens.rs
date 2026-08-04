fn signed_ready(
    authority_id: [u8; 16],
    host_id: [u8; 16],
    keys: &gocode_api::ProtectedActivationKeys,
) -> ProtectedReadyV1 {
    let mut ready = ProtectedReadyV1::new(
        authority_id,
        host_id,
        executable(),
        profile(),
        stable(),
        INSTANCE_ID,
        7,
        SESSION_ID,
        "https://127.0.0.1:43123",
        [0x31; 32],
        vec![1, 2, 3, 4],
        vec!["conversation-replay-v2".to_owned()],
    )
    .expect("ready");
    ready.sign(keys);
    ready
}

fn pending_first_activation() -> PendingFirstActivationV1 {
    PendingFirstActivationV1::new(
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 7,
        ],
        [0x41; 32],
        stable(),
        executable(),
        profile(),
    )
    .expect("pending first activation")
}

fn v1_lifecycle_frames() -> Vec<(&'static str, u32, Vec<u8>)> {
    let secret = LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret");
    let keys = secret.derive_keys();
    let request = launch(secret);
    let ready = signed_ready(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        &keys,
    );
    let owned = ready.owned_launch();
    let mut renewal = ProtectedRenewRequestV1::new(owned.clone(), 1, [0x71; 32]).unwrap();
    renewal.sign(&keys);
    let mut ticket = ProtectedRenewTicketV1::new(
        &renewal,
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 6,
        ],
        [0x72; 32],
        1_000,
        31_000,
    )
    .unwrap();
    ticket.sign(&keys);
    let mut shutdown = ProtectedShutdownV1::new(owned.clone());
    shutdown.sign(&keys);
    let mut acknowledgement = ProtectedShutdownAckV1::new(owned, true);
    acknowledgement.sign(&keys);
    let first_request = launch_with_disposition(
        LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"),
        ActivationDispositionV1::FirstActivation,
    );
    let first_keys = first_request.derive_keys();
    let pending = pending_first_activation();
    let mut prepared = ProtectedFirstActivationPreparedV1::new(
        first_request.launch_authority_id(),
        first_request.desktop_host_instance_id(),
        pending.clone(),
    );
    prepared.sign(&first_keys);
    let mut commit = ProtectedFirstActivationCommitV1::new(
        first_request.launch_authority_id(),
        first_request.desktop_host_instance_id(),
        pending,
    );
    commit.sign(&first_keys);
    vec![
        ("launch", 1, request.encode_frame().unwrap()),
        ("ready", 2, ready.encode_frame().unwrap()),
        ("renew_request", 3, renewal.encode_frame().unwrap()),
        ("renew_ticket", 4, ticket.encode_frame().unwrap()),
        ("shutdown", 5, shutdown.encode_frame().unwrap()),
        ("shutdown_ack", 6, acknowledgement.encode_frame().unwrap()),
        ("first_activation_prepared", 7, prepared.encode_frame().unwrap()),
        ("first_activation_commit", 8, commit.encode_frame().unwrap()),
    ]
}

fn v2_lifecycle_frames() -> Vec<(&'static str, u32, Vec<u8>)> {
    let request = launch_v2(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    let keys = request.derive_keys();
    let base_ready = signed_ready(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        &keys,
    );
    let mut ready = ProtectedReadyV2::new(base_ready, openai_binding()).unwrap();
    ready.sign(&keys);
    let owned = ready.owned_launch();
    let mut renewal = ProtectedRenewRequestV2::new(owned.clone(), 1, [0x71; 32]).unwrap();
    renewal.sign(&keys);
    let mut ticket = ProtectedRenewTicketV2::new(
        &renewal,
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 6,
        ],
        [0x72; 32],
        1_000,
        31_000,
    )
    .unwrap();
    ticket.sign(&keys);
    let mut shutdown = ProtectedShutdownV2::new(owned.clone());
    shutdown.sign(&keys);
    let mut acknowledgement = ProtectedShutdownAckV2::new(owned, true);
    acknowledgement.sign(&keys);
    vec![
        ("launch", 21, request.encode_frame().unwrap()),
        ("ready", 22, ready.encode_frame().unwrap()),
        ("renew_request", 23, renewal.encode_frame().unwrap()),
        ("renew_ticket", 24, ticket.encode_frame().unwrap()),
        ("shutdown", 25, shutdown.encode_frame().unwrap()),
        ("shutdown_ack", 26, acknowledgement.encode_frame().unwrap()),
    ]
}

macro_rules! assert_wire_golden {
    ($golden:expr, $name:expr, $type_id:expr, $frame:expr, $decoder:ty) => {{
        let expected = if $name == "launch" {
            platform_launch_golden(&$golden)
        } else {
            &$golden["lifecycle_messages"][$name]
        };
        assert_eq!(expected["message_type_id"], $type_id, "{} type", $name);
        assert_eq!(expected["frame_length"], $frame.len(), "{} length", $name);
        assert_eq!(
            expected["frame_sha256"],
            hex_digest(Sha256::digest($frame)),
            "{} digest",
            $name
        );
        assert!(<$decoder>::decode_frame($frame).is_ok(), "{} decode", $name);

        let mut unknown = $frame.clone();
        unknown[5] = 16;
        assert!(<$decoder>::decode_frame(&unknown).is_err(), "{} unknown", $name);

        let mut duplicate = $frame.clone();
        let type_length = usize::from(duplicate[6] >= 24) + 1;
        duplicate[6 + type_length] = 0;
        assert!(<$decoder>::decode_frame(&duplicate).is_err(), "{} duplicate", $name);

        let mut truncated = $frame.clone();
        truncated.pop();
        assert!(<$decoder>::decode_frame(&truncated).is_err(), "{} truncated", $name);
    }};
}

#[test]
fn protected_activation_lifecycle_wire_goldens_are_stable_and_strict() {
    let v1: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/golden/protected-bundled-activation-v1.json"
    ))
    .unwrap();
    let v2: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/golden/protected-bundled-activation-v2.json"
    ))
    .unwrap();
    let v1_frames = v1_lifecycle_frames();
    let v2_frames = v2_lifecycle_frames();
    for (name, type_id, frame) in v1_frames {
        match name {
            "launch" => assert_wire_golden!(v1, name, type_id, &frame, ProtectedLaunchRequestV1),
            "ready" => assert_wire_golden!(v1, name, type_id, &frame, ProtectedReadyV1),
            "renew_request" => assert_wire_golden!(v1, name, type_id, &frame, ProtectedRenewRequestV1),
            "renew_ticket" => assert_wire_golden!(v1, name, type_id, &frame, ProtectedRenewTicketV1),
            "shutdown" => assert_wire_golden!(v1, name, type_id, &frame, ProtectedShutdownV1),
            "shutdown_ack" => assert_wire_golden!(v1, name, type_id, &frame, ProtectedShutdownAckV1),
            "first_activation_prepared" => assert_wire_golden!(v1, name, type_id, &frame, ProtectedFirstActivationPreparedV1),
            "first_activation_commit" => assert_wire_golden!(v1, name, type_id, &frame, ProtectedFirstActivationCommitV1),
            _ => unreachable!("covered V1 lifecycle message"),
        }
    }
    for (name, type_id, frame) in v2_frames {
        match name {
            "launch" => assert_wire_golden!(v2, name, type_id, &frame, ProtectedLaunchRequestV2),
            "ready" => assert_wire_golden!(v2, name, type_id, &frame, ProtectedReadyV2),
            "renew_request" => assert_wire_golden!(v2, name, type_id, &frame, ProtectedRenewRequestV2),
            "renew_ticket" => assert_wire_golden!(v2, name, type_id, &frame, ProtectedRenewTicketV2),
            "shutdown" => assert_wire_golden!(v2, name, type_id, &frame, ProtectedShutdownV2),
            "shutdown_ack" => assert_wire_golden!(v2, name, type_id, &frame, ProtectedShutdownAckV2),
            _ => unreachable!("covered V2 lifecycle message"),
        }
    }
}
