mod local;

#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "the protected V2 host remains unmounted until trusted writer admission is composed"
    )
)]
pub(crate) use local::LocalProviderCredentialVerification;
