use super::model::MAX_SAFE_JS_INTEGER;
use super::*;

fn binding() -> RunBinding {
    RunBinding::new(
        "run-42", [1; 20], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32],
    )
    .unwrap()
}
fn offer() -> BootstrapControlReply {
    BootstrapControlReply::DesktopOffer(
        DesktopOffer::new([7; 32], [8; 32], binding(), 10, 11).unwrap(),
    )
}
fn ack() -> BootstrapControlReply {
    BootstrapControlReply::BootstrapAck(
        BootstrapAck::new([8; 32], [9; 32], binding(), [10; 32], MAX_SAFE_JS_INTEGER).unwrap(),
    )
}
fn root_prepared() -> BootstrapControlReply {
    BootstrapControlReply::RootPrepared(RootPrepared::new([8; 32], binding(), 10, 11).unwrap())
}
fn root_issued_proof() -> BootstrapControlReply {
    BootstrapControlReply::RootIssuedProof(
        RootIssuedProof::new([8; 32], [9; 32], vec![255; 2_048]).unwrap(),
    )
}

#[test]
fn canonical_round_trips_each_closed_kind() {
    let requests = [
        BootstrapControlRequest::DesktopOffer(DesktopOfferRequest::new([1; 32]).unwrap())
            .encode()
            .unwrap(),
        BootstrapControlRequest::RuntimeBootstrap(
            RuntimeBootstrapRequest::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]).unwrap(),
        )
        .encode()
        .unwrap(),
        BootstrapControlRequest::RootConsume(
            RootConsumeRequest::new([1; 32], [2; 32], vec![255; 2_048]).unwrap(),
        )
        .encode()
        .unwrap(),
        BootstrapControlRequest::RootPrepare(RootPrepareRequest::new())
            .encode()
            .unwrap(),
        BootstrapControlRequest::RootArm(
            RootArmRequest::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]).unwrap(),
        )
        .encode()
        .unwrap(),
    ];
    for bytes in requests {
        let decoded = BootstrapControlRequest::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
    }
    for bytes in [
        offer().encode().unwrap(),
        ack().encode().unwrap(),
        root_prepared().encode().unwrap(),
        root_issued_proof().encode().unwrap(),
    ] {
        let decoded = BootstrapControlReply::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
    }
}

#[test]
fn root_service_kinds_are_fixed() {
    let requests = [
        (
            BootstrapControlRequest::RootPrepare(RootPrepareRequest::new()),
            "root_prepare",
        ),
        (
            BootstrapControlRequest::RootArm(
                RootArmRequest::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]).unwrap(),
            ),
            "root_arm",
        ),
    ];
    for (request, kind) in requests {
        assert!(
            String::from_utf8(request.encode().unwrap())
                .unwrap()
                .contains(&format!("\"kind\":\"{kind}\""))
        );
    }
    for (reply, kind) in [
        (root_prepared(), "root_prepared"),
        (root_issued_proof(), "root_issued_proof"),
    ] {
        assert!(
            String::from_utf8(reply.encode().unwrap())
                .unwrap()
                .contains(&format!("\"kind\":\"{kind}\""))
        );
    }
}

#[test]
fn root_service_messages_reject_wrong_shapes() {
    let prepare = BootstrapControlRequest::RootPrepare(RootPrepareRequest::new())
        .encode()
        .unwrap();
    let prepare = String::from_utf8(prepare).unwrap();
    assert!(
        BootstrapControlRequest::decode(prepare.replacen('}', ",\"offer_id\":[1]}", 1).as_bytes())
            .is_err()
    );

    let arm = BootstrapControlRequest::RootArm(
        RootArmRequest::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]).unwrap(),
    )
    .encode()
    .unwrap();
    let arm = String::from_utf8(arm).unwrap();
    assert!(
        BootstrapControlRequest::decode(
            arm.replacen("\"candidate_sha256\"", "\"unexpected\"", 1)
                .as_bytes()
        )
        .is_err()
    );

    let prepared = String::from_utf8(root_prepared().encode().unwrap()).unwrap();
    assert!(
        BootstrapControlReply::decode(
            prepared
                .replacen('}', ",\"desktop_challenge\":[1]}", 1)
                .as_bytes()
        )
        .is_err()
    );

    let issued_proof = String::from_utf8(root_issued_proof().encode().unwrap()).unwrap();
    assert!(
        BootstrapControlReply::decode(
            issued_proof
                .replacen("\"signed_proof\":\"", "\"signed_proof\":\"+", 1)
                .as_bytes()
        )
        .is_err()
    );
}

#[test]
fn rejects_role_kind_domain_and_version_substitution() {
    let request = BootstrapControlRequest::DesktopOffer(DesktopOfferRequest::new([1; 32]).unwrap())
        .encode()
        .unwrap();
    for (from, to) in [
        ("request", "reply"),
        ("desktop_offer_request", "bootstrap_ack"),
        (QUALIFICATION_BOOTSTRAP_CONTROL_DOMAIN, "other"),
        ("\"version\":1", "\"version\":2"),
    ] {
        let text = String::from_utf8(request.clone())
            .unwrap()
            .replacen(from, to, 1);
        assert!(BootstrapControlRequest::decode(text.as_bytes()).is_err());
    }
    let reply = offer().encode().unwrap();
    assert!(BootstrapControlRequest::decode(&reply).is_err());
    assert!(BootstrapControlReply::decode(&request).is_err());
}

#[test]
fn rejects_unknown_duplicate_noncanonical_trailing_and_oversize_messages() {
    let bytes = BootstrapControlRequest::DesktopOffer(DesktopOfferRequest::new([1; 32]).unwrap())
        .encode()
        .unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for rejected in [
        format!("{text} "),
        text.replacen('}', ",\"unknown\":1}", 1),
        text.replacen(
            "\"role\":\"request\"",
            "\"role\":\"request\",\"role\":\"request\"",
            1,
        ),
    ] {
        assert!(BootstrapControlRequest::decode(rejected.as_bytes()).is_err());
    }
    assert!(
        BootstrapControlRequest::decode(&vec![b'x'; MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES + 1])
            .is_err()
    );
}

#[test]
fn rejects_zero_values_invalid_run_ids_and_time_boundaries() {
    assert!(
        RunBinding::new(
            "run/42", [1; 20], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]
        )
        .is_err()
    );
    assert!(
        RunBinding::new(
            "run-42", [0; 20], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]
        )
        .is_err()
    );
    assert!(DesktopOfferRequest::new([0; 32]).is_err());
    assert!(RootConsumeRequest::new([1; 32], [2; 32], vec![]).is_err());
    assert!(
        RootConsumeRequest::new(
            [1; 32],
            [2; 32],
            vec![1; MAX_QUALIFICATION_BOOTSTRAP_SIGNED_PROOF_BYTES + 1]
        )
        .is_err()
    );
    assert!(DesktopOffer::new([1; 32], [2; 32], binding(), 0, 1).is_err());
    assert!(DesktopOffer::new([1; 32], [2; 32], binding(), 2, 1).is_err());
    assert!(RootPrepared::new([0; 32], binding(), 1, 1).is_err());
    assert!(RootIssuedProof::new([1; 32], [2; 32], vec![]).is_err());
    assert!(
        RootIssuedProof::new(
            [1; 32],
            [2; 32],
            vec![1; MAX_QUALIFICATION_BOOTSTRAP_SIGNED_PROOF_BYTES + 1]
        )
        .is_err()
    );
    assert!(
        DesktopOffer::new(
            [1; 32],
            [2; 32],
            binding(),
            MAX_SAFE_JS_INTEGER,
            MAX_SAFE_JS_INTEGER
        )
        .is_ok()
    );
    assert!(
        BootstrapAck::new(
            [1; 32],
            [2; 32],
            binding(),
            [3; 32],
            MAX_SAFE_JS_INTEGER + 1
        )
        .is_err()
    );
}
