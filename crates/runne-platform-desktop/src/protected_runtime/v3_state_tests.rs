include!("v3_state_fixture.rs");

#[test]
fn v3_launch_rejects_v1_and_v2_readiness_frames() {
    let (launch, ready, v1_ready, keys) = v3_fixture();
    let request = DesktopLaunchRequest::V3(launch);
    let v2_ready = v2_ready(v1_ready.clone(), &keys);

    assert!(matches!(
        request.decode_ready(&v1_ready.encode_frame().expect("V1 ready frame"), &keys),
        Err(LaunchAuthorityError::ReadinessProofMismatch)
    ));
    assert!(matches!(
        request.decode_ready(&v2_ready.encode_frame().expect("V2 ready frame"), &keys),
        Err(LaunchAuthorityError::ReadinessProofMismatch)
    ));
    assert!(
        request
            .decode_ready(&ready.encode_frame().expect("V3 ready frame"), &keys)
            .is_ok()
    );
}

#[test]
fn exact_v3_ready_retains_the_enrollment_binding_in_process_activation() {
    let (launch, ready, _, keys) = v3_fixture();
    let binding = launch.enrollment_binding().clone();
    let request = DesktopLaunchRequest::V3(launch);
    let ready = request
        .decode_ready(&ready.encode_frame().expect("V3 ready frame"), &keys)
        .expect("exact V3 ready");
    let activation = ready
        .into_process_activation(request)
        .expect("matching V3 process activation");

    assert_eq!(activation.enrollment_binding(), Some(&binding));
}

#[test]
fn exact_v3_ready_is_retained_and_builds_a_direct_v3_runtime_profile() {
    let (launch, ready, _, keys) = v3_fixture();
    let request = DesktopLaunchRequest::V3(launch);
    let decoded = request
        .decode_ready(&ready.encode_frame().expect("V3 ready frame"), &keys)
        .expect("exact V3 ready");
    let profile = request
        .runtime_profile(&decoded, 15, &keys)
        .expect("direct V3 runtime profile");
    let activation = decoded
        .into_process_activation(request)
        .expect("V3 process activation");

    assert_eq!(activation.v3_ready(), Some(&ready));
    assert_eq!(profile.enrollment_owned_launch(), Some(&ready.owned_launch()));
}

#[test]
fn v3_has_no_compatibility_projection_or_unwind_path() {
    let (launch, ready, _, keys) = v3_fixture();
    let request = DesktopLaunchRequest::V3(launch);
    let decoded = request
        .decode_ready(&ready.encode_frame().expect("V3 ready frame"), &keys)
        .expect("exact V3 ready");
    let activation = decoded
        .into_process_activation(request)
        .expect("V3 process activation");

    assert!(activation.compatibility_ready().is_none());
    assert!(activation.compatibility_owned().is_none());
}

#[test]
fn v3_renewal_rejects_cross_protocol_and_out_of_window_tickets() {
    let (activation, keys, v1_ticket, v2_ticket, v3_request, v3_ticket) =
        v3_activation_with_tickets();

    assert!(
        activation
            .verify_v3_renewal_frame(
                &v3_request,
                &v1_ticket.encode_frame().expect("V1 ticket frame"),
                100,
                &keys
            )
            .is_err()
    );
    assert!(
        activation
            .verify_v3_renewal_frame(
                &v3_request,
                &v2_ticket.encode_frame().expect("V2 ticket frame"),
                100,
                &keys
            )
            .is_err()
    );
    assert!(
        activation
            .verify_v3_renewal_frame(
                &v3_request,
                &v3_ticket.encode_frame().expect("V3 ticket frame"),
                99,
                &keys
            )
            .is_err()
    );
    assert!(
        activation
            .verify_v3_renewal_frame(
                &v3_request,
                &v3_ticket.encode_frame().expect("V3 ticket frame"),
                201,
                &keys
            )
            .is_err()
    );

    let renewed = activation
        .verify_v3_renewal_frame(
            &v3_request,
            &v3_ticket.encode_frame().expect("V3 ticket frame"),
            100,
            &keys,
        )
        .expect("fresh exact V3 ticket");
    assert_ne!(*renewed.bootstrap_ticket(), [0; 32]);
    assert_eq!(
        Some(renewed.enrollment_binding()),
        activation.enrollment_binding()
    );
}

#[test]
fn v3_shutdown_rejects_cross_protocol_and_substituted_binding_acknowledgements() {
    let (activation, keys, v1_ready, v3_ready) = v3_activation();
    let v2_ready = v2_ready(v1_ready.clone(), &keys);
    let v1_ack = signed_v1_ack(v1_ready.owned_launch(), &keys);
    let v2_ack = signed_v2_ack(v2_ready.owned_launch(), &keys);
    let substituted = signed_v3_ack(substituted_owned(), &keys);

    assert!(
        activation
            .verify_v3_shutdown_ack(&v1_ack.encode_frame().expect("V1 ack frame"), &keys)
            .is_err()
    );
    assert!(
        activation
            .verify_v3_shutdown_ack(&v2_ack.encode_frame().expect("V2 ack frame"), &keys)
            .is_err()
    );
    assert!(
        activation
            .verify_v3_shutdown_ack(
                &substituted
                    .encode_frame()
                    .expect("substituted V3 ack frame"),
                &keys
            )
            .is_err()
    );

    let exact = signed_v3_ack(v3_ready.owned_launch(), &keys);
    assert!(
        activation
            .verify_v3_shutdown_ack(&exact.encode_frame().expect("V3 ack frame"), &keys)
            .expect("exact V3 acknowledgement")
    );
}
