#[test]
#[cfg(target_os = "macos")]
fn native_confirmation_uses_renewed_v3_owned_session_without_compatibility_projection() {
    let (mut activation, keys, _, _, request, ticket) = v3_activation_with_tickets();
    let next = ticket
        .verify_exact_at(&request, 100, &keys)
        .unwrap()
        .next_owned_launch();
    let ProtectedProcessActivation::V3 { owned, .. } = &mut activation else {
        panic!("V3 fixture")
    };
    *owned = next;
    let confirmation = activation.native_confirmation([31; 32], [31; 32]).unwrap();
    assert_eq!(confirmation.session, id(23));
    assert_eq!(confirmation.daemon, id(12));
    assert_eq!(confirmation.launch_authority, id(1));
    assert_eq!(confirmation.desktop_host, id(2));
    assert_eq!(confirmation.generation, 1);
    assert!(activation.compatibility_owned().is_none());
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_confirmation_preserves_v2_and_rejects_unbound_v1() {
    let (request, ready, _) = v2_launch_fixture();
    let v1 = DesktopReady::V1(ready.compatibility_ready().clone())
        .into_process_activation(DesktopLaunchRequest::V1(
            request.compatibility_request().clone(),
        ))
        .unwrap();
    assert!(v1.native_confirmation([31; 32], [31; 32]).is_err());
    let v2 = DesktopReady::V2(ready)
        .into_process_activation(DesktopLaunchRequest::V2(request))
        .unwrap();
    let confirmation = v2.native_confirmation([31; 32], [31; 32]).unwrap();
    assert_eq!(confirmation.session, id(13));
    assert_eq!(confirmation.daemon, id(12));
    assert_eq!(confirmation.process_start_before, [31; 32]);
    assert_eq!(confirmation.process_start_after, [31; 32]);
}

#[test]
fn installed_enrollment_confirmation_requires_a_ready_supervisor() {
    let fixture = crate::tests::OwnerPrivateBundledRuntimeFixture::new();
    let spec = ProtectedBundledRuntimeLaunchSpec::new(fixture.daemon(), &fixture.runtime_root())
        .expect("trusted launch spec");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);

    let error = supervisor
        .confirm_installed_native_enrollment(
            crate::PreparedInstalledNativeEnrollment::test_only_for_state_rejection(),
        )
        .expect_err("an absent supervisor must not mint enrollment evidence");

    assert_eq!(error, ProtectedBundledRuntimeError::InvalidState);
    supervisor.state = BundledRuntimeLifecycleState::Handshaking;
    assert_eq!(
        supervisor.pending_profile_is_v3(),
        Err(ProtectedBundledRuntimeError::InvalidState)
    );
}

#[test]
fn installed_enrollment_evidence_has_no_copyable_or_serializable_surface() {
    let source = include_str!("../updater_metadata/enrollment_tuple/live_daemon.rs");
    for forbidden in [
        "derive(Clone",
        "impl Clone for PreparedInstalledNativeEnrollment",
        "impl Clone for ConfirmedInstalledNativeEnrollment",
        "impl Serialize for",
        "pub fn session",
        "pub fn daemon",
        "pub fn release_tuple",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden evidence surface: {forbidden}"
        );
    }
}

#[test]
fn enrollment_transition_queues_v3_profile_before_any_writer_handoff_surface() {
    let source = include_str!("native_enrollment.rs");
    assert!(!source.contains("begin_credential_enrollment_handoff"));
    let transition = source
        .find("begin_credential_enrollment_transition")
        .expect("split transition entry point");
    let queued = source[transition..]
        .find("self.pending_profile = Some(profile)")
        .expect("transitioned profile retained by supervisor");
    let handoff = source
        .find("pub fn run_credential_writer_handoff")
        .expect("separate post-Begin handoff entry point");
    assert!(transition + queued < handoff);
}

#[cfg(target_os = "linux")]
#[test]
fn inherited_socketpair_peer_credentials_name_the_creator_not_child() {
    use std::{os::fd::OwnedFd, os::unix::net::UnixStream, process::{Command, Stdio}};
    let (desktop, child_end) = UnixStream::pair().unwrap();
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::from(OwnedFd::from(child_end)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let peer = rustix::net::sockopt::socket_peercred(&desktop).unwrap();
    assert_eq!(u32::try_from(peer.pid.as_raw_pid()).unwrap(), std::process::id());
    assert_ne!(child.id(), std::process::id());
    child.kill().unwrap();
    child.wait().unwrap();
}
