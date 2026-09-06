use syn::{Fields, Visibility};

pub const DAEMON_SOURCE: &str =
    "runne-daemon/src/protected_activation/control_v3/initial_exchange.rs";

pub fn exact_daemon_carrier(source: &str, item: &syn::ItemStruct) -> bool {
    let expected: syn::ItemStruct = syn::parse_str(
        "#[cfg(target_os = \"macos\")] pub(crate) struct VerifiedQualificationAdmission { _admission: runne_native_qualification::PendingQualificationAdmission }",
    )
    .unwrap();
    let Fields::Named(fields) = &item.fields else {
        return false;
    };
    source == DAEMON_SOURCE
        && item.ident == expected.ident
        && item.vis == expected.vis
        && item.attrs == expected.attrs
        && item.generics.params.is_empty()
        && item.generics.where_clause.is_none()
        && fields.named.len() == 1
        && fields.named.iter().all(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|name| name == "_admission")
                && matches!(field.vis, Visibility::Inherited)
                && matches!(&field.ty, syn::Type::Path(path)
                    if path.path.segments.last().is_some_and(|part|
                        part.ident == "PendingQualificationAdmission"))
        })
}

pub fn exact_initial_read(source: &str, item: &syn::ItemFn) -> bool {
    let expected: syn::ItemFn = syn::parse_str(
        "#[cfg(target_os = \"macos\")] pub(super) fn read_admitted_initial_request(channel: &mut ProtectedActivationChannel, keys: &ProtectedActivationKeys, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, _enrollment: &mut super::runtime::V3EnrollmentDispatch) -> Result<(Zeroizing<Vec<u8>>, Option<VerifiedQualificationAdmission>), LaunchAuthorityError> { todo!() }",
    ).unwrap();
    source == DAEMON_SOURCE
        && item.attrs == expected.attrs
        && item.vis == expected.vis
        && signatures_match(&item.sig, &expected.sig)
}

pub const SESSION_SOURCE: &str = "runne-daemon/src/application/provider_credential_enrollment/control_facade/protected_session.rs";
pub const TRANSFER_SOURCE: &str = "runne-daemon/src/application/provider_credential_enrollment/control_facade/protected_session/qualification.rs";

pub fn exact_session_carrier(
    source: &str,
    item: &syn::ItemStruct,
    aliases: &std::collections::HashSet<String>,
) -> bool {
    let expected: syn::ItemStruct = syn::parse_str(
        "pub(crate) struct DaemonProtectedCredentialEnrollmentSession { #[cfg(all(target_os = \"macos\", feature = \"desktop-protected\"))] qualification: Option<crate::protected_activation::control_v3::initial_exchange::VerifiedQualificationAdmission> }",
    ).unwrap();
    let sensitive: Vec<_> = item
        .fields
        .iter()
        .filter(|field| crate::installed_surface_syntax::type_mentions(&field.ty, aliases))
        .collect();
    source == SESSION_SOURCE
        && item.ident == expected.ident
        && item.vis == expected.vis
        && item.generics == expected.generics
        && crate::installed_surface_syntax::sealed_struct(item)
        && sensitive == expected.fields.iter().collect::<Vec<_>>()
}

pub fn exact_session_transfer(source: &str, owner: &syn::Type, method: &syn::ImplItemFn) -> bool {
    let expected: syn::ImplItemFn = syn::parse_str(
        "pub(crate) fn retain_qualification(mut self, qualification: VerifiedQualificationAdmission) -> Result<Self, ProviderCredentialEnrollmentHostError> { todo!() }",
    ).unwrap();
    source == TRANSFER_SOURCE
        && matches!(owner, syn::Type::Path(path) if path.path.is_ident("DaemonProtectedCredentialEnrollmentSession"))
        && method.vis == expected.vis
        && method.attrs.iter().all(|attr| attr.path().is_ident("doc"))
        && signatures_match(&method.sig, &expected.sig)
}

pub fn exact_retention_helper(source: &str, item: &syn::ItemFn) -> bool {
    let expected: syn::ItemFn = syn::parse_str(
        "#[cfg(target_os = \"macos\")] fn verify_and_retain_qualification_admission(installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, verifier: &mut runne_native_qualification::QualificationAdmissionVerifier, admission: runne_native_qualification::PendingQualificationAdmission, now_unix_seconds: u64) -> Result<VerifiedQualificationAdmission, LaunchAuthorityError> { todo!() }",
    )
    .unwrap();
    source == DAEMON_SOURCE
        && item.attrs == expected.attrs
        && item.vis == expected.vis
        && signatures_match(&item.sig, &expected.sig)
}

fn signatures_match(actual: &syn::Signature, expected: &syn::Signature) -> bool {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}

pub fn exact_initial_result(source: &str, item: &syn::ItemEnum) -> bool {
    let expected: syn::ItemEnum = syn::parse_str(
        "#[cfg(target_os = \"macos\")] enum InitialQualificationFrame { Legacy(Zeroizing<Vec<u8>>), Verified(VerifiedQualificationAdmission), }",
    )
    .unwrap();
    source == DAEMON_SOURCE
        && item.attrs == expected.attrs
        && item.ident == expected.ident
        && item.vis == expected.vis
        && item.generics == expected.generics
        && item.variants == expected.variants
}
