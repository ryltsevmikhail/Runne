use super::*;

impl Fixture {
    pub(in super::super) fn legacy_cleanup_after_rotation() -> Self {
        let mut fixture = Self::legacy_cleanup(FailurePoint::None);
        fixture.lifecycle = CredentialLifecycleSnapshot::new(
            provider(),
            Some(CredentialVersionRef::new(provider(), 2).unwrap()),
            revision(3),
            fence(3),
            readiness(3),
            3,
        )
        .unwrap();
        fixture.successor = fixture.lifecycle.clone();
        fixture
    }
}

pub(super) fn binding() -> runne_provider::CredentialLegacyCleanupBinding {
    runne_provider::CredentialLegacyCleanupBinding::from_parts(
        CredentialOperationId::from_bytes([8; 16]).unwrap(),
        revision(1),
        fence(1),
        CredentialVersionRef::new(provider(), 1).unwrap(),
        digest(13),
    )
}
