use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn compose(
    binding: RuntimeSessionBinding,
    launch_authority_id: [u8; 16],
    executable_sha256: [u8; 32],
    bootstrap_secret: [u8; 32],
    reservation_store: Arc<SqliteBootstrapReservationStore>,
    enrollment_generation_store: StoreTransaction,
    protected: bool,
) -> Result<Arc<Mutex<LocalSessionService>>, DaemonError> {
    let service = if protected {
        LocalSessionService::new_protected_with_stores(
            binding,
            launch_authority_id,
            executable_sha256,
            bootstrap_secret,
            reservation_store,
            Arc::new(enrollment_generation_store),
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .map_err(|_| DaemonError::Bootstrap("initialize protected session".into()))?
    } else {
        LocalSessionService::with_reservation_store(
            binding,
            launch_authority_id,
            executable_sha256,
            bootstrap_secret,
            reservation_store,
        )
    };
    Ok(Arc::new(Mutex::new(service)))
}
