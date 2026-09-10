use super::PreparedInstalledNativeEnrollment;

impl PreparedInstalledNativeEnrollment {
    pub(crate) fn matches_qualified_daemon(
        &self, digest: [u8; 32], release: [u8; 32], qualification: [u8; 32], now: u64,
    ) -> bool {
        self.admission.as_ref().is_some_and(|admission| {
            admission.daemon_sha256 == digest && admission.release_tuple_sha256 == release
                && admission.qualification.matches_exact(release, qualification, now)
        })
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::super::*;

    #[test]
    fn v3_confirmation_requires_exact_qualified_daemon_and_current_lease() {
        let fixture = crate::updater_metadata::enrollment_daemon_installed::tests::signed_fixture_admission();
        let digest = fixture.admission.daemon_sha256;
        let prepared = PreparedInstalledNativeEnrollment { admission: Some(fixture.admission), paths: None };
        assert!(prepared.matches_qualified_daemon(digest, fixture.release, fixture.qualification, fixture.expires_at - 1));
        assert!(!prepared.matches_qualified_daemon([99; 32], fixture.release, fixture.qualification, fixture.expires_at - 1));
        assert!(!prepared.matches_qualified_daemon(digest, [99; 32], fixture.qualification, fixture.expires_at - 1));
        assert!(!prepared.matches_qualified_daemon(digest, fixture.release, [99; 32], fixture.expires_at - 1));
        assert!(!prepared.matches_qualified_daemon(digest, fixture.release, fixture.qualification, fixture.expires_at));
    }
}
