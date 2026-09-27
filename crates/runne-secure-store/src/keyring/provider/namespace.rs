use crate::SecureStoreError;
#[cfg(any(
    test,
    all(target_os = "linux", feature = "linux-native-enrollment-qualification")
))]
use sha2::{Digest, Sha256};

#[cfg(any(
    test,
    all(target_os = "linux", feature = "linux-native-enrollment-qualification")
))]
const QUALIFICATION_NAMESPACE_DOMAIN: &[u8] =
    b"runne/secure-store/linux-qualification-profile-namespace/v1\0";

#[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
pub(super) fn service_prefix() -> Result<String, SecureStoreError> {
    let profile_id = option_env!("RUNNE_UPDATE_PROFILE_ID");
    #[cfg(any(test, feature = "test-support"))]
    let profile_id = profile_id.or(Some("dev-linux-test-fixture"));
    qualification_service_prefix(profile_id)
}

#[cfg(not(all(target_os = "linux", feature = "linux-native-enrollment-qualification")))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "callers share a fallible API with qualification builds, where the profile may be unavailable"
)]
pub(super) fn service_prefix() -> Result<String, SecureStoreError> {
    Ok(crate::PROVIDER_CREDENTIAL_SERVICE.to_owned())
}

#[cfg(any(
    test,
    all(target_os = "linux", feature = "linux-native-enrollment-qualification")
))]
fn qualification_service_prefix(profile_id: Option<&str>) -> Result<String, SecureStoreError> {
    let profile_id = profile_id.ok_or(SecureStoreError::Unavailable)?;
    let suffix = profile_id
        .strip_prefix("dev-linux-")
        .ok_or(SecureStoreError::Unavailable)?;
    if suffix.is_empty()
        || suffix.len() > 64
        || !suffix.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._-".contains(&byte))
        })
    {
        return Err(SecureStoreError::Unavailable);
    }
    let mut digest = Sha256::new();
    digest.update(QUALIFICATION_NAMESPACE_DOMAIN);
    digest.update(profile_id.as_bytes());
    let encoded: [u8; 32] = digest.finalize().into();
    let mut hex = String::with_capacity(64);
    for byte in encoded {
        use core::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    Ok(format!(
        "{}.qualification.{hex}",
        crate::PROVIDER_CREDENTIAL_SERVICE
    ))
}

#[cfg(test)]
mod tests {
    use super::{qualification_service_prefix, service_prefix};
    #[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
    use crate::SecureStoreError;

    #[test]
    fn qualification_prefix_is_stable_separate_and_never_defaults_to_global() {
        let first = qualification_service_prefix(Some("dev-linux-profile-a")).unwrap();
        let same = qualification_service_prefix(Some("dev-linux-profile-a")).unwrap();
        let second = qualification_service_prefix(Some("dev-linux-profile-b")).unwrap();
        assert_eq!(first, same);
        assert_ne!(first, second);
        assert!(qualification_service_prefix(None).is_err());
        assert!(qualification_service_prefix(Some("foreign-profile")).is_err());
        assert!(qualification_service_prefix(Some("dev-linux-")).is_err());
        assert!(qualification_service_prefix(Some("dev-linux-profile/one")).is_err());
        assert!(qualification_service_prefix(Some("dev-linux-profile ")).is_err());
        assert!(
            qualification_service_prefix(Some(&format!("dev-linux-{}", "a".repeat(65)))).is_err()
        );

        assert_ne!(first, second);
    }

    #[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
    #[test]
    fn qualification_operations_never_select_the_legacy_namespace() {
        assert!(service_prefix().unwrap().starts_with(&format!(
            "{}.qualification.",
            crate::PROVIDER_CREDENTIAL_SERVICE
        )));
        assert_eq!(
            qualification_service_prefix(None),
            Err(SecureStoreError::Unavailable)
        );
    }

    #[cfg(not(all(target_os = "linux", feature = "linux-native-enrollment-qualification")))]
    #[test]
    fn ordinary_builds_keep_the_legacy_namespace() {
        assert_eq!(
            service_prefix().unwrap(),
            crate::PROVIDER_CREDENTIAL_SERVICE
        );
    }
}
