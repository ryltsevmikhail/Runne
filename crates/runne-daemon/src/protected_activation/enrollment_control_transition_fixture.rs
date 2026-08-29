//! Shared fixture for the same-process enrollment control transition tests.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use runne_api::{
    ActivationDispositionV1, ApiPrincipalId, DaemonInstanceId, ExecutableIdentityV1, LaunchSecret,
    PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, ProtectedCredentialEnrollmentPrepareV2,
    ProtectedLaunchRequestV1, ProtectedLaunchRequestV2, ProtectedOwnedLaunchV2, ProtectedReadyV1,
    ProtectedRuntimeProfileV1, ProviderActivationBindingV1, ProviderActivationReadinessV1,
    RuntimeSessionBinding, StableRuntimeBinding, StableRuntimeBindingV1,
};
use runne_application::local_session::{
    BootstrapReservationError, BootstrapReservationStore, ConsumeReservation, ConsumedReservation,
    EnrollmentLaunchGenerationConsumeError, EnrollmentLaunchGenerationStore, LocalSessionService,
    PreallocateReservation, Reservation,
};
use runne_domain::{event::Sensitivity, id::EventLogLineageId};

use super::enrollment_control_transition::EnrollmentControlComposition;

pub(super) fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

pub(super) fn profile() -> ProtectedRuntimeProfileV1 {
    ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "fixture",
        [1; 32],
        [2; 32],
    )
    .unwrap()
}

pub(super) fn executable() -> ExecutableIdentityV1 {
    ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap()
}

pub(super) fn stable_v1() -> StableRuntimeBindingV1 {
    StableRuntimeBindingV1::new(id(10), "local-owner", id(11), "fixture", [1; 32], [2; 32]).unwrap()
}

pub(super) fn v2_launch() -> (
    ProtectedLaunchRequestV2,
    ProtectedOwnedLaunchV2,
    runne_api::ProtectedActivationKeys,
    ProviderActivationBindingV1,
) {
    v2_launch_with_secret([3; 32])
}

pub(super) fn v2_launch_with_secret(
    secret: [u8; 32],
) -> (
    ProtectedLaunchRequestV2,
    ProtectedOwnedLaunchV2,
    runne_api::ProtectedActivationKeys,
    ProviderActivationBindingV1,
) {
    let request = ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        LaunchSecret::from_bytes(secret).unwrap(),
        1_000,
        20_000,
        "local-owner",
        profile(),
        executable(),
        "/tmp/runtime".into(),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let keys = request.derive_keys();
    let ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        executable(),
        profile(),
        stable_v1(),
        id(12),
        4,
        id(13),
        "https://127.0.0.1:9",
        [14; 32],
        vec![14; 8],
        vec!["provider.enroll".into()],
    )
    .unwrap();
    let provider = ProviderActivationBindingV1::openai_responses_text_v1();
    let original = ProtectedLaunchRequestV2::new(request, provider.clone()).unwrap();
    let owned = ProtectedOwnedLaunchV2::new(ready.owned_launch(), provider.clone()).unwrap();
    (original, owned, keys, provider)
}

pub(super) fn prepare_and_owned(
    owned: &ProtectedOwnedLaunchV2,
    keys: &runne_api::ProtectedActivationKeys,
) -> ProtectedCredentialEnrollmentPrepareV2 {
    let mut prepare = ProtectedCredentialEnrollmentPrepareV2::new(
        owned.clone(),
        1,
        [21; 32],
        [7; 32],
        [8; 32],
        [9; 32],
        1,
    )
    .unwrap();
    prepare.sign(keys);
    prepare
}

pub(super) fn composition(original: &ProtectedLaunchRequestV2) -> EnrollmentControlComposition {
    EnrollmentControlComposition::new(
        original.clone(),
        [6; 32],
        ProviderActivationReadinessV1::Ready,
        "https://127.0.0.1:9".into(),
        [14; 32],
        vec![14; 8],
        vec!["provider.credential-enrollment.v2".into()],
        std::path::PathBuf::from("/tmp"),
        Arc::new(|| Ok(1_000)),
    )
}

pub(super) fn session_binding(generation: u64, session: [u8; 16]) -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            id(10),
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000013"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "profile",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(id(12)),
        generation,
        session,
        7,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}

pub(super) struct CountedGenerationStore {
    pub(super) next_reserve: AtomicU64,
    pub(super) reserved: AtomicU64,
}

impl CountedGenerationStore {
    pub(super) fn starting_at(value: u64) -> Arc<Self> {
        Arc::new(Self {
            next_reserve: AtomicU64::new(value),
            reserved: AtomicU64::new(0),
        })
    }
}

impl EnrollmentLaunchGenerationStore for CountedGenerationStore {
    fn consume_reserved_enrollment_generation(
        &self,
        generation: u64,
    ) -> Result<(), EnrollmentLaunchGenerationConsumeError> {
        if generation != 0 && generation == self.reserved.load(Ordering::Relaxed) {
            Ok(())
        } else {
            Err(EnrollmentLaunchGenerationConsumeError::Rejected)
        }
    }

    fn reserve_next_enrollment_generation(
        &self,
    ) -> Result<u64, EnrollmentLaunchGenerationConsumeError> {
        let value = self.next_reserve.fetch_add(1, Ordering::Relaxed);
        self.reserved.store(value, Ordering::Relaxed);
        Ok(value)
    }
}

pub(super) struct UnavailableReservationStore;

impl BootstrapReservationStore for UnavailableReservationStore {
    fn preallocate(
        &self,
        _: PreallocateReservation,
    ) -> Result<Reservation, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }

    fn consume_final(
        &self,
        _: ConsumeReservation<'_>,
    ) -> Result<ConsumedReservation, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }

    fn observe_clock(&self, _: i64) -> Result<i64, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }
}

pub(super) fn protected_service(
    store: &Arc<CountedGenerationStore>,
) -> (Arc<Mutex<LocalSessionService>>, RuntimeSessionBinding) {
    let current = session_binding(4, [5; 16]);
    let service = LocalSessionService::new_protected_with_stores(
        current.clone(),
        [1; 16],
        [2; 32],
        [0x22; 32],
        Arc::new(UnavailableReservationStore),
        Arc::clone(store) as Arc<dyn EnrollmentLaunchGenerationStore>,
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    (Arc::new(Mutex::new(service)), current)
}
