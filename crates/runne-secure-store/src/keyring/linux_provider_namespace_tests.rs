use super::super::provider::{provider_key, version_key};
use super::{CountingFakeSource, PROVIDER_SERVICE, install_test_source, serial};
use crate::provider_credential::ProviderCredentialId;
use runne_provider::{CredentialVersionRef, ProviderId};

#[test]
fn qualification_provider_and_version_routes_are_isolated_from_legacy_items() {
    let _guard = serial();
    let provider = ProviderCredentialId::DeepSeek;
    let reference =
        CredentialVersionRef::new(ProviderId::new(provider.account()).expect("provider id"), 1)
            .expect("version reference");
    let (scoped_provider_service, account) = provider_key(provider).expect("scoped provider key");
    let (scoped_version_service, version_account) =
        version_key(&reference).expect("scoped version key");
    let legacy_version_service = legacy_version_service(&reference);
    assert_ne!(scoped_provider_service, PROVIDER_SERVICE);
    assert_ne!(scoped_version_service, legacy_version_service);
    assert_eq!(account, provider.account());
    assert_eq!(version_account, provider.account());

    let mut fake = CountingFakeSource::unlocked();
    fake.entries.insert(
        (PROVIDER_SERVICE.to_owned(), provider.account().to_owned()),
        b"legacy-provider".to_vec(),
    );
    fake.entries.insert(
        (
            legacy_version_service.clone(),
            provider.account().to_owned(),
        ),
        b"legacy-version".to_vec(),
    );
    let _source = install_test_source(Box::new(fake));

    assert!(
        super::super::NativeKeyringStore::read_secret(&scoped_provider_service, &account)
            .expect("scoped provider does not fall back")
            .is_none()
    );
    assert!(
        super::super::NativeKeyringStore::read_secret(&scoped_version_service, &version_account)
            .expect("scoped version does not fall back")
            .is_none()
    );
    super::super::NativeKeyringStore::write_secret(
        &scoped_provider_service,
        &account,
        b"profile-provider",
    )
    .expect("scoped provider write");
    super::super::NativeKeyringStore::write_secret(
        &scoped_version_service,
        &version_account,
        b"profile-version",
    )
    .expect("scoped version write");
    assert_eq!(
        *super::super::NativeKeyringStore::read_secret(&scoped_provider_service, &account)
            .expect("scoped provider read")
            .expect("scoped provider item"),
        b"profile-provider".to_vec()
    );
    assert_eq!(
        *super::super::NativeKeyringStore::read_secret(&scoped_version_service, &version_account)
            .expect("scoped version read")
            .expect("scoped version item"),
        b"profile-version".to_vec()
    );
    assert_eq!(
        *super::super::NativeKeyringStore::read_secret(PROVIDER_SERVICE, provider.account())
            .expect("legacy provider read")
            .expect("legacy provider remains"),
        b"legacy-provider".to_vec()
    );
    assert_eq!(
        *super::super::NativeKeyringStore::read_secret(&legacy_version_service, provider.account())
            .expect("legacy version read")
            .expect("legacy version remains"),
        b"legacy-version".to_vec()
    );

    super::super::NativeKeyringStore::delete_secret(&scoped_provider_service, &account)
        .expect("scoped provider delete");
    super::super::NativeKeyringStore::delete_secret(&scoped_version_service, &version_account)
        .expect("scoped version delete");
    assert!(
        super::super::NativeKeyringStore::read_secret(&scoped_provider_service, &account)
            .expect("scoped provider absent")
            .is_none()
    );
    assert!(
        super::super::NativeKeyringStore::read_secret(&scoped_version_service, &version_account)
            .expect("scoped version absent")
            .is_none()
    );
    assert!(
        super::super::NativeKeyringStore::read_secret(PROVIDER_SERVICE, provider.account())
            .expect("legacy provider unchanged")
            .is_some()
    );
    assert!(
        super::super::NativeKeyringStore::read_secret(&legacy_version_service, provider.account())
            .expect("legacy version unchanged")
            .is_some()
    );
}

#[test]
fn background_account_has_distinct_provider_and_version_keyring_accounts() {
    let openai = ProviderCredentialId::OpenAi;
    let background = ProviderCredentialId::OpenAiBackground;
    let openai_ref =
        CredentialVersionRef::new(ProviderId::new(openai.account()).unwrap(), 1).unwrap();
    let background_ref =
        CredentialVersionRef::new(ProviderId::new(background.account()).unwrap(), 1).unwrap();
    let (_, openai_account) = provider_key(openai).unwrap();
    let (_, background_account) = provider_key(background).unwrap();
    let (_, openai_version_account) = version_key(&openai_ref).unwrap();
    let (_, background_version_account) = version_key(&background_ref).unwrap();

    assert_eq!(openai_account, "openai");
    assert_eq!(background_account, "openai-background");
    assert_eq!(openai_version_account, "openai");
    assert_eq!(background_version_account, "openai-background");
}

fn legacy_version_service(reference: &CredentialVersionRef) -> String {
    use core::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in reference.ref_digest() {
        let _ = write!(&mut digest, "{byte:02x}");
    }
    format!(
        "{PROVIDER_SERVICE}.version.{}.{}",
        reference.version(),
        digest
    )
}
