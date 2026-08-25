fn re_adopt_process(
    launcher: &NativeOwnerBoundProcessLauncher,
    handle: OwnedProcessHandleV1,
) -> Result<(), OwnerBoundProcessError> {
    #[cfg(target_os = "linux")]
    native_linux::verify_re_adoption(&handle)?;
    #[cfg(target_os = "windows")]
    native_windows::verify_re_adoption(&handle)?;
    #[cfg(target_os = "macos")]
    native_macos::verify_re_adoption(&handle)?;
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    return Err(OwnerBoundProcessError::LifecycleRejected);

    let mut active = launcher
        .active
        .lock()
        .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
    if active.contains_key(&handle.pid()) {
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    active.insert(
        handle.pid(),
        ActiveProcess {
            #[cfg(unix)]
            child: None,
            #[cfg(windows)]
            child: None,
            pid: handle.pid(),
            start_identity: *handle.start_identity(),
            launch_nonce: *handle.launch_nonce(),
            output: Arc::new(Mutex::new(Vec::new())),
        },
    );
    Ok(())
}
