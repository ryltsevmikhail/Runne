async fn commit_prepared_admission(
    prepared: &PreparedWorkspaceManager,
    reservation: PreparedWorkspaceReservationGuard,
    native_admission: NativeRootAdmission,
    lifecycle: &RuntimeLifecycleManager,
) -> Result<PreparedWorkspaceResponse, ()> {
    let (root, admission, operation_permit) = native_admission.into_parts();
    let mut operation_permit = Some(operation_permit);
    if prepared
        .commit(
            reservation.reference(),
            root,
            admission,
            &mut operation_permit,
            std::time::Instant::now(),
        )
        .is_err()
    {
        lifecycle
            .reap_failed_root_admission(operation_permit.expect("permit remains on failed commit"))
            .await;
        return Err(());
    }
    Ok(PreparedWorkspaceResponse::new(reservation.disarm()))
}
