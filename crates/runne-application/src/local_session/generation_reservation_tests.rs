enum ReservedGenerationStore {
    Value(u64),
    Error(EnrollmentLaunchGenerationConsumeError),
}

impl EnrollmentLaunchGenerationStore for ReservedGenerationStore {
    fn consume_reserved_enrollment_generation(
        &self,
        _: u64,
    ) -> Result<(), EnrollmentLaunchGenerationConsumeError> {
        Ok(())
    }

    fn reserve_next_enrollment_generation(
        &self,
    ) -> Result<u64, EnrollmentLaunchGenerationConsumeError> {
        match self {
            Self::Value(generation) => Ok(*generation),
            Self::Error(error) => Err(*error),
        }
    }
}

enum FixedGenerationStore {
    Result(Result<(), EnrollmentLaunchGenerationConsumeError>),
    Panic,
}

impl EnrollmentLaunchGenerationStore for FixedGenerationStore {
    fn consume_reserved_enrollment_generation(
        &self,
        _: u64,
    ) -> Result<(), EnrollmentLaunchGenerationConsumeError> {
        match self {
            Self::Result(result) => *result,
            Self::Panic => panic!("pure local validation must reject before consumption"),
        }
    }

    fn reserve_next_enrollment_generation(
        &self,
    ) -> Result<u64, EnrollmentLaunchGenerationConsumeError> {
        Err(EnrollmentLaunchGenerationConsumeError::Rejected)
    }
}

#[test]
fn protected_reservation_accepts_only_the_exact_successor() {
    let current = rotation_binding(4, [5; 16], 7, Sensitivity::Internal, [6; 32]);
    let make = |store| {
        LocalSessionService::new_protected_with_stores(
            current.clone(), [1; 16], [2; 32], [0x22; 32],
            Arc::new(UnavailableBootstrapReservationStore), Arc::new(store),
            Duration::ZERO, Duration::from_secs(30),
        ).unwrap()
    };
    assert_eq!(make(ReservedGenerationStore::Value(5)).reserve_protected_enrollment_generation(), Ok(5));
    for store in [
        ReservedGenerationStore::Value(0),
        ReservedGenerationStore::Value(4),
        ReservedGenerationStore::Value(6),
        ReservedGenerationStore::Error(EnrollmentLaunchGenerationConsumeError::Rejected),
    ] {
        assert_eq!(make(store).reserve_protected_enrollment_generation(), Err(LocalSessionError::Unauthorized));
    }
    assert_eq!(make(ReservedGenerationStore::Error(EnrollmentLaunchGenerationConsumeError::Unavailable)).reserve_protected_enrollment_generation(), Err(LocalSessionError::Unavailable));
}

#[test]
fn protected_reservation_overflow_is_rejected_before_the_store_and_binding_is_unchanged() {
    let current = rotation_binding(u64::MAX, [5; 16], 7, Sensitivity::Internal, [6; 32]);
    let service = LocalSessionService::new_protected_with_stores(
        current.clone(), [1; 16], [2; 32], [0x22; 32],
        Arc::new(UnavailableBootstrapReservationStore),
        Arc::new(ReservedGenerationStore::Value(u64::MAX)),
        Duration::ZERO, Duration::from_secs(30),
    ).unwrap();
    assert_eq!(
        service.reserve_protected_enrollment_generation(),
        Err(LocalSessionError::Unauthorized)
    );
    assert_eq!(service.current_binding(), &current);
}

#[test]
fn successful_reservation_never_mutates_the_in_memory_binding() {
    let current = rotation_binding(4, [5; 16], 7, Sensitivity::Internal, [6; 32]);
    let service = LocalSessionService::new_protected_with_stores(
        current.clone(), [1; 16], [2; 32], [0x22; 32],
        Arc::new(UnavailableBootstrapReservationStore),
        Arc::new(ReservedGenerationStore::Value(5)),
        Duration::ZERO, Duration::from_secs(30),
    ).unwrap();
    assert_eq!(service.reserve_protected_enrollment_generation(), Ok(5));
    assert_eq!(service.current_binding(), &current);
}

#[test]
fn unprotected_policy_never_reserves_enrollment_generations() {
    let service = LocalSessionService::new(
        rotation_binding(4, [5; 16], 7, Sensitivity::Internal, [6; 32]),
        [0x22; 32],
    );
    assert_eq!(
        service.reserve_protected_enrollment_generation(),
        Err(LocalSessionError::Unauthorized)
    );
}
