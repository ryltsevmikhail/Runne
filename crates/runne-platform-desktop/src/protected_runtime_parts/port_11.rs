#[cfg(unix)]
fn validate_owner_private_file(file: &File) -> Result<(), ProtectedBundledRuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProtectedBundledRuntimeError::ActivationStateUnavailable)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::tests::OwnerPrivateBundledRuntimeFixture;

    fn owner_private_tempdir() -> tempfile::TempDir {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect temporary directory");
        temporary
    }

    fn executable(path: &Path, mode: u32) {
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").expect("write executable fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set executable permissions");
    }

    fn stable() -> StableRuntimeBindingV1 {
        let profile = expected_profile().expect("expected profile");
        StableRuntimeBindingV1::new(
            *uuid::Uuid::now_v7().as_bytes(),
            LOCAL_PRINCIPAL,
            *uuid::Uuid::now_v7().as_bytes(),
            profile.profile_id(),
            *profile.profile_hash(),
            *profile.capability_digest(),
        )
        .expect("stable binding")
    }

    #[test]
    fn protected_launcher_profile_is_the_exact_extended_capability_tuple() {
        let profile = expected_profile().expect("expected protected profile");
        let protected = PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        let base = runne_runtime_client::REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            profile.capability_digest(),
            &ordered_capability_digest(&protected)
        );
        assert_ne!(
            profile.capability_digest(),
            &ordered_capability_digest(&base)
        );
        let qualified = runne_runtime_client::ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES;
        let qualified_profile = profile_for_capabilities(qualified).expect("qualified profile");
        assert_ne!(
            qualified_profile.capability_digest(),
            profile.capability_digest()
        );
        assert_eq!(qualified_profile.profile_hash(), profile.profile_hash());
        assert_eq!(
            qualified_profile.capability_digest(),
            &ordered_capability_digest(
                &qualified
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>(),
            )
        );
    }

    #[test]
    fn qualified_release_requires_provider_bound_launch() {
        let base = expected_profile().unwrap();
        assert_eq!(selected_launch_profile(false, true).unwrap(), base);
        assert_eq!(selected_launch_profile(true, false).unwrap(), base);
        assert_ne!(selected_launch_profile(true, true).unwrap(), base);
    }

    #[test]
    fn launch_spec_rejects_relative_symlink_and_writable_executables() {
        let temporary = owner_private_tempdir();
        let runtime_root = temporary.path().join("runtime");
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(Path::new("relative-runned"), &runtime_root,),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );

        let writable = temporary.path().join("writable-runned");
        executable(&writable, 0o777);
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(&writable, &runtime_root),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );

        let target = temporary.path().join("target-runned");
        executable(&target, 0o755);
        let link = temporary.path().join("linked-runned");
        std::os::unix::fs::symlink(&target, &link).expect("create executable symlink");
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(&link, &runtime_root),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );

        let writable_parent = temporary.path().join("writable-parent");
        std::fs::create_dir(&writable_parent).expect("create writable parent");
        std::fs::set_permissions(&writable_parent, std::fs::Permissions::from_mode(0o777))
            .expect("weaken parent permissions");
        let unsafe_daemon = writable_parent.join("runned");
        executable(&unsafe_daemon, 0o755);
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(&unsafe_daemon, &runtime_root),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );

        let group_writable_parent = temporary.path().join("group-writable-parent");
        std::fs::create_dir(&group_writable_parent).expect("create group-writable parent");
        std::fs::set_permissions(
            &group_writable_parent,
            std::fs::Permissions::from_mode(0o770),
        )
        .expect("weaken parent group permissions");
        let group_daemon = group_writable_parent.join("runned");
        executable(&group_daemon, 0o755);
        assert_eq!(
            ProtectedBundledRuntimeLaunchSpec::new(&group_daemon, &runtime_root),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );
    }

    #[test]
    fn directory_write_bits_match_the_macos_release_reality() {
        let euid = rustix::process::geteuid().as_raw();
        // The privileged-group allowance exists for the macOS release
        // reality (stock /Applications is root:admin 0775, no sticky bit);
        // on other unix systems gid 80 carries no privileged meaning and
        // the pre-existing sticky-bit rule applies unchanged.
        let applications_shape_accepted = cfg!(target_os = "macos");
        assert_eq!(
            directory_write_bits_are_secure(0o775, 0, 80, 1234, euid),
            applications_shape_accepted,
        );
        assert_eq!(
            directory_write_bits_are_secure(0o775, 0, 0, 1234, euid),
            applications_shape_accepted,
        );
        assert!(!directory_write_bits_are_secure(0o775, 0, 20, euid, euid));
        assert!(!directory_write_bits_are_secure(0o777, 0, 80, euid, euid));
        assert!(!directory_write_bits_are_secure(0o775, 1000, 80, 1000, 1000));
        assert!(!directory_write_bits_are_secure(0o770, 1000, 1000, 1000, 1000));
        assert!(directory_write_bits_are_secure(0o1775, 1000, 80, 0, 1000));
        assert!(!directory_write_bits_are_secure(0o1775, 1000, 80, 1001, 1002));
        assert!(directory_write_bits_are_secure(0o1777, 0, 80, euid, euid));
        assert!(!directory_write_bits_are_secure(0o1777, 0, 80, 1001, euid));
        assert!(directory_write_bits_are_secure(0o755, 0, 80, 1001, euid));
    }

    #[test]
    fn launch_rejects_source_replacement_after_identity_is_pinned() {
        let fixture = OwnerPrivateBundledRuntimeFixture::new();
        let daemon = fixture.daemon();
        let spec = ProtectedBundledRuntimeLaunchSpec::new(daemon, &fixture.runtime_root())
            .expect("trusted launch spec");
        std::fs::set_permissions(daemon, std::fs::Permissions::from_mode(0o700))
            .expect("permit controlled replacement");
        std::fs::write(daemon, b"#!/bin/sh\nexit 7\n").expect("replace source bytes");
        std::fs::set_permissions(daemon, std::fs::Permissions::from_mode(0o500))
            .expect("restore executable permissions");

        assert_eq!(
            DevelopmentBundledRuntimeLauncher::new()
                .launch(&spec)
                .expect_err("replacement must fail before protected admission"),
            ProtectedBundledRuntimeError::ExecutableIdentityMismatch
        );
    }

    #[test]
    fn discovery_uses_only_the_exact_colocated_packaged_daemon_name() {
        let fixture = OwnerPrivateBundledRuntimeFixture::new();
        let desktop = fixture.desktop();
        let daemon = fixture.daemon();

        assert_eq!(
            discover_bundled_runtime(desktop).expect("discover protected daemon"),
            std::fs::canonicalize(daemon).expect("canonical daemon")
        );

        std::fs::set_permissions(daemon, std::fs::Permissions::from_mode(0o775))
            .expect("weaken daemon permissions");
        assert_eq!(
            discover_bundled_runtime(desktop),
            Err(ProtectedBundledRuntimeError::ExecutableUnavailable)
        );
    }

    #[test]
    fn activation_records_are_exact_owner_private_and_non_secret() {
        let temporary = owner_private_tempdir();
        let store = ActivationStateStore::open(temporary.path()).expect("state store");
        let expected_stable = stable();
        store
            .persist_stable_exact(&expected_stable, &mut LaunchTestControls::production())
            .expect("persist stable");
        assert_eq!(
            store.load_stable().expect("load stable"),
            Some(expected_stable)
        );

        let path = store.directory.join(STABLE_RECORD_FILE);
        let bytes = std::fs::read(&path).expect("read stable record");
        let text = String::from_utf8(bytes).expect("stable JSON");
        assert!(!text.contains("launch_secret"));
        assert!(!text.contains("bootstrap"));
        assert!(!text.contains("credential"));
        assert_eq!(
            std::fs::metadata(path)
                .expect("stable metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&store.directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let different = stable();
        assert_eq!(
            store.persist_stable_exact(&different, &mut LaunchTestControls::production()),
            Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
        );
    }

    #[test]
    fn activation_record_with_weakened_acl_is_rejected() {
        let temporary = owner_private_tempdir();
        let store = ActivationStateStore::open(temporary.path()).expect("state store");
        store
            .persist_stable_exact(&stable(), &mut LaunchTestControls::production())
            .expect("persist stable");
        let path = store.directory.join(STABLE_RECORD_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("weaken stable permissions");
        assert_eq!(
            store.load_stable(),
            Err(ProtectedBundledRuntimeError::ActivationStateUnavailable)
        );
    }

    #[test]
    fn concrete_supervisor_exhausts_the_bounded_restart_budget() {
        let fixture = OwnerPrivateBundledRuntimeFixture::new();
        let spec =
            ProtectedBundledRuntimeLaunchSpec::new(fixture.daemon(), &fixture.runtime_root())
                .expect("launch spec");
        let mut supervisor =
            ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
        let now = Instant::now();

        for _ in 0..5 {
            supervisor
                .schedule_restart(now)
                .expect("restart remains available");
            assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Backoff);
        }
        assert_eq!(
            supervisor.schedule_restart(now),
            Err(ProtectedBundledRuntimeError::RestartExhausted)
        );
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Exhausted);
    }
}
