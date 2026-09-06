use syn::{Fields, Visibility};

pub const DAEMON_SOURCE: &str =
    "runne-daemon/src/protected_activation/control_v3/initial_exchange.rs";

pub fn exact_daemon_carrier(source: &str, item: &syn::ItemStruct) -> bool {
    let expected: syn::ItemStruct = syn::parse_str(
        "#[cfg(target_os = \"macos\")] struct VerifiedQualificationAdmission { _admission: runne_native_qualification::PendingQualificationAdmission }",
    )
    .unwrap();
    let Fields::Named(fields) = &item.fields else {
        return false;
    };
    source == DAEMON_SOURCE
        && item.ident == expected.ident
        && matches!(item.vis, Visibility::Inherited)
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
