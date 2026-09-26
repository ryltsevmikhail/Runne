fn v3_process(channel: UnixStream) -> (ProtectedBundledRuntimeProcess, ProtectedActivationKeys) {
    let (launch, ready, _, keys) = v3_fixture();
    let signer_keys = launch.derive_keys();
    let request = DesktopLaunchRequest::V3(launch);
    let ready = request
        .decode_ready(&ready.encode_frame().expect("V3 ready frame"), &keys)
        .expect("exact V3 ready");
    let activation = ready
        .into_process_activation(request)
        .expect("V3 activation");
    let child = Command::new("/bin/sh")
        .args(["-c", "sleep 60"])
        .spawn()
        .expect("owned test child");
    (
        ProtectedBundledRuntimeProcess {
            child,
            #[cfg(target_os = "linux")]
            linux_launch_image: None,
            channel,
            keys,
            activation,
            runtime_profile: None,
            renewal_sequence: 0,
            #[cfg(feature = "protected-channel-integration")]
            root_control_sequence: 0,
            graceful_requested: false, graceful_acknowledged: false,
            enrollment_broker_facts: None,
            #[cfg(feature = "test-support")]
            captured_stdout: None,
            #[cfg(feature = "test-support")]
            captured_stderr: None,
        },
        signer_keys,
    )
}

fn scripted_v3_process<F>(reply: F) -> (ProtectedBundledRuntimeProcess, std::thread::JoinHandle<()>)
where
    F: FnOnce(
            &mut UnixStream,
            &runne_api::ProtectedCredentialEnrollmentRenewRequestV3,
            &ProtectedActivationKeys,
        ) + Send
        + 'static,
{
    let (desktop, mut daemon) = UnixStream::pair().expect("test channel");
    let (process, keys) = v3_process(desktop);
    let server = std::thread::spawn(move || {
        let frame = read_frame(&mut daemon).expect("V3 renewal frame");
        let renewal = runne_api::ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&frame)
            .expect("exact V3 renewal");
        reply(&mut daemon, &renewal, &keys);
    });
    (process, server)
}

fn closed_v3_process() -> ProtectedBundledRuntimeProcess {
    let (desktop, daemon) = UnixStream::pair().expect("test channel");
    drop(daemon);
    v3_process(desktop).0
}

fn signed_v3_ticket(
    renewal: &runne_api::ProtectedCredentialEnrollmentRenewRequestV3,
    keys: &ProtectedActivationKeys,
    issued: u64,
    expires: u64,
) -> Vec<u8> {
    let mut ticket = runne_api::ProtectedCredentialEnrollmentRenewTicketV3::new(
        renewal,
        id(23),
        [24; 32],
        issued,
        expires,
    )
    .expect("V3 ticket");
    ticket.sign(keys);
    ticket.encode_frame().expect("V3 ticket frame")
}

fn v3_owned(
    process: &ProtectedBundledRuntimeProcess,
) -> runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3 {
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!("V3 process");
    };
    owned.clone()
}

fn assert_v3_renewal_fenced(process: &mut ProtectedBundledRuntimeProcess) {
    assert_eq!(
        process.status(),
        Ok(BundledRuntimeProcessStatus::Exited),
        "the ambiguous renewal child must be fenced"
    );
    assert!(matches!(
        process.renew_v3_profile_for_test(|| Ok(100)),
        Err(ProtectedBundledRuntimeError::InvalidState)
    ));
    assert_eq!(
        write_frame(&mut process.channel, &[0, 0, 0, 1, 0]),
        Err(ProtectedBundledRuntimeError::ProtectedChannelUnavailable)
    );
}

#[test]
fn v3_renewal_accepts_a_ticket_at_the_shared_continuous_tick() {
    let (mut process, server) = scripted_v3_process(move |daemon, renewal, keys| {
        let frame = signed_v3_ticket(renewal, keys, 100, 200);
        write_frame(daemon, &frame).expect("ticket response");
    });
    let clock_samples = std::cell::Cell::new(0);

    let profile = process
        .renew_v3_profile_for_test(|| {
            clock_samples.set(clock_samples.get() + 1);
            Ok(100)
        })
        .expect("shared continuous tick");
    server.join().expect("ticket server");

    assert_eq!(clock_samples.get(), 1);
    assert_eq!(process.renewal_sequence, 1);
    assert_eq!(profile.enrollment_owned_launch(), Some(&v3_owned(&process)));
}

#[test]
fn v3_renewal_rejects_v1_and_v2_ticket_frames_without_advancing_state() {
    for frame in [
        signed_v1_renewal_ticket_frame(),
        signed_v2_renewal_ticket_frame(),
    ] {
        let (mut process, server) = scripted_v3_process(move |daemon, _, _| {
            write_frame(daemon, &frame).expect("cross-protocol response");
        });
        let initial = v3_owned(&process);

        assert!(process.renew_v3_profile_for_test(|| Ok(100)).is_err());
        server.join().expect("ticket server");
        assert_eq!(process.renewal_sequence, 0);
        assert_eq!(v3_owned(&process), initial);
        assert_v3_renewal_fenced(&mut process);
    }
}

#[test]
fn v3_renewal_clock_failure_fences_the_child_and_control_channel() {
    let (release, held_server) = std::sync::mpsc::channel();
    let (mut process, server) = scripted_v3_process(move |daemon, renewal, keys| {
        write_frame(daemon, &signed_v3_ticket(renewal, keys, 100, 200)).expect("ticket response");
        held_server.recv().expect("release ticket server");
    });
    let initial = v3_owned(&process);

    assert!(matches!(
        process.renew_v3_profile_for_test(|| Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::RenewalUnavailable
        ))),
        Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::RenewalUnavailable
        ))
    ));
    assert_eq!(process.renewal_sequence, 0);
    assert_eq!(v3_owned(&process), initial);
    assert_v3_renewal_fenced(&mut process);
    release.send(()).expect("release ticket server");
    server.join().expect("ticket server");
}

#[test]
fn v3_renewal_write_failure_fences_before_a_partial_delivery_can_be_retried() {
    let mut process = closed_v3_process();
    let initial = v3_owned(&process);

    assert!(matches!(
        process.renew_v3_profile_for_test(|| Ok(100)),
        Err(ProtectedBundledRuntimeError::ProtectedChannelUnavailable)
    ));
    assert_eq!(process.renewal_sequence, 0);
    assert_eq!(v3_owned(&process), initial);
    assert_v3_renewal_fenced(&mut process);
}

#[test]
fn v3_renewal_rejects_stale_and_future_ticket_ticks_without_advancing_state() {
    for now in [99, 201] {
        let (mut process, server) = scripted_v3_process(|daemon, renewal, keys| {
            write_frame(daemon, &signed_v3_ticket(renewal, keys, 100, 200))
                .expect("ticket response");
        });
        let initial = v3_owned(&process);

        assert!(process.renew_v3_profile_for_test(|| Ok(now)).is_err());
        server.join().expect("ticket server");
        assert_eq!(process.renewal_sequence, 0);
        assert_eq!(v3_owned(&process), initial);
    }
}

#[test]
fn v3_renewal_rejects_a_suspend_jump_without_advancing_state() {
    let (mut process, server) = scripted_v3_process(|daemon, renewal, keys| {
        write_frame(daemon, &signed_v3_ticket(renewal, keys, 100, 200)).expect("ticket response");
    });
    let initial = v3_owned(&process);

    assert!(process.renew_v3_profile_for_test(|| Ok(231)).is_err());
    server.join().expect("ticket server");
    assert_eq!(process.renewal_sequence, 0);
    assert_eq!(v3_owned(&process), initial);
}

fn signed_v1_renewal_ticket_frame() -> Vec<u8> {
    let (_, _, ready, keys) = v3_fixture();
    let mut renewal =
        ProtectedRenewRequestV1::new(ready.owned_launch(), 1, [41; 32]).expect("V1 renewal");
    renewal.sign(&keys);
    let mut ticket =
        ProtectedRenewTicketV1::new(&renewal, id(42), [43; 32], 100, 200).expect("V1 ticket");
    ticket.sign(&keys);
    ticket.encode_frame().expect("V1 ticket frame")
}

fn signed_v2_renewal_ticket_frame() -> Vec<u8> {
    let (_, _, ready, keys) = v3_fixture();
    let ready = v2_ready(ready, &keys);
    let mut renewal =
        ProtectedRenewRequestV2::new(ready.owned_launch(), 1, [44; 32]).expect("V2 renewal");
    renewal.sign(&keys);
    let mut ticket =
        ProtectedRenewTicketV2::new(&renewal, id(45), [46; 32], 100, 200).expect("V2 ticket");
    ticket.sign(&keys);
    ticket.encode_frame().expect("V2 ticket frame")
}
