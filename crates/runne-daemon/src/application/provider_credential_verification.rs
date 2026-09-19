mod local;
mod profiles;
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
mod remote;

#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "the protected V2 host remains unmounted until trusted writer admission is composed"
    )
)]
pub(crate) use local::LocalProviderCredentialVerification;
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(crate) use remote::RemoteProviderCredentialVerification;

#[cfg(test)]
mod tests;
