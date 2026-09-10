use syn::{Fields, Visibility};

pub const DAEMON_SOURCE: &str =
    "runne-daemon/src/protected_activation/control_v3/initial_exchange.rs";
const SESSION_TEST_SUPPORT_SOURCE: &str =
    "runne-daemon/src/protected_activation/control_v3/initial_exchange/session_test_support.rs";

pub fn exact_daemon_carrier(source: &str, item: &syn::ItemStruct) -> bool {
    let expected: syn::ItemStruct = syn::parse_str(
        "#[cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))] pub(crate) struct VerifiedQualificationAdmission { _admission: runne_native_qualification::PendingQualificationAdmission }",
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
        && fields.named.len() == 3
        && fields.named.iter().all(|field| {
            matches!(field.vis, Visibility::Inherited) && match field.ident.as_ref().map(ToString::to_string).as_deref() {
                Some("_admission") => matches!(&field.ty, syn::Type::Path(path)
                    if path.path.segments.last().is_some_and(|part| part.ident == "PendingQualificationAdmission")),
                Some("owned") => field.ty == syn::parse_str::<syn::Type>("Box<runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3>").unwrap(),
                Some("members") => field.ty == syn::parse_str::<syn::Type>("qualification_fence::QualificationAdmissionMembers").unwrap(),
                _ => false,
            }
        })
}

pub fn exact_connected_test_fixture(source: &str, item: &syn::ItemStruct) -> bool {
    let expected: syn::ItemStruct = syn::parse_str(
        "pub(crate) struct ConnectedQualificationFixture { pub(crate) installed: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, pub(crate) admission: super::VerifiedQualificationAdmission, pub(crate) verifier: runne_native_qualification::QualificationAdmissionVerifier, receiver: ConnectedQualificationReceiver, pub(crate) now: u64, }",
    )
    .unwrap();
    source == SESSION_TEST_SUPPORT_SOURCE
        && item.ident == expected.ident
        && item.vis == expected.vis
        && item.fields == expected.fields
        && item.generics == expected.generics
        && item.attrs.is_empty()
}

pub fn exact_connected_test_transfer(
    source: &str,
    owner: &syn::Type,
    method: &syn::ImplItemFn,
) -> bool {
    let expected: syn::ImplItemFn = syn::parse_str(
        "pub(crate) fn into_parts(self) -> (runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, super::VerifiedQualificationAdmission, runne_native_qualification::QualificationAdmissionVerifier, ConnectedQualificationReceiver, u64,) {}",
    )
    .unwrap();
    source == SESSION_TEST_SUPPORT_SOURCE
        && matches!(owner, syn::Type::Path(path) if path.path.is_ident("ConnectedQualificationFixture"))
        && method.vis == expected.vis
        && method.attrs.is_empty()
        && signatures_match(&method.sig, &expected.sig)
}

pub fn exact_fence_wrapper(source: &str, item: &syn::ItemStruct) -> bool {
    if source != TRANSFER_SOURCE {
        return false;
    }
    let expected = match item.ident.to_string().as_str() {
        "CommittedQualification" => {
            "struct CommittedQualification { admission: VerifiedQualificationAdmission, receipt: ProviderQualificationAdmissionFenceReceipt, qualified: QualifiedIssuedTicket, fingerprint: [u8; 32], continuation: CredentialBindingDigest, }"
        }
        "FencedQualificationAdmission" => {
            "pub(super) struct FencedQualificationAdmission { _admission: VerifiedQualificationAdmission, _receipt: runne_provider::ProviderQualificationAdmissionFenceReceipt, }"
        }
        _ => return false,
    };
    let expected: syn::ItemStruct = syn::parse_str(expected).unwrap();
    item.vis == expected.vis
        && item.fields == expected.fields
        && item.generics == expected.generics
        && item.attrs.iter().all(|attr| attr.path().is_ident("doc"))
}

pub fn exact_fence_reverification(source: &str, item: &syn::ItemImpl) -> bool {
    if source
        != "runne-daemon/src/protected_activation/control_v3/initial_exchange/qualification_fence.rs"
        || item.trait_.is_some()
        || !item.generics.params.is_empty()
        || item.items.len() != 3
    {
        return false;
    }
    item.items.iter().all(|member| {
        let syn::ImplItem::Fn(method) = member else { return false; };
        let expected = match method.sig.ident.to_string().as_str() {
            "retained_owned" => "pub(crate) fn retained_owned(&self) -> &ProtectedCredentialEnrollmentOwnedLaunchV3 {}",
            "into_postcommit" => "pub(crate) fn into_postcommit(self, qualified: QualifiedIssuedTicket, permit: PostcommitAdmissionPermit) -> PostcommitQualificationAdmission {}",
            "reverify_for_fence" => "pub(crate) fn reverify_for_fence(&self, installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, current: &ProtectedCredentialEnrollmentOwnedLaunchV3, verifier: &mut runne_native_qualification::QualificationAdmissionVerifier, now_unix_seconds: u64) -> Result<runne_native_qualification::VerifiedQualificationFenceFacts, Error> {}",
            _ => return false,
        };
        let expected: syn::ImplItemFn = syn::parse_str(expected).unwrap();
        method.vis == expected.vis && signatures_match(&method.sig, &expected.sig)
    })
}

pub fn exact_initial_read(source: &str, item: &syn::ItemFn) -> bool {
    let expected: syn::ItemFn = syn::parse_str(
        "#[cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))] pub(super) fn read_admitted_initial_request(channel: &mut ProtectedActivationChannel, keys: &ProtectedActivationKeys, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, _enrollment: &mut super::runtime::V3EnrollmentDispatch) -> Result<(Zeroizing<Vec<u8>>, Option<VerifiedQualificationAdmission>), LaunchAuthorityError> { todo!() }",
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
        "pub(crate) struct DaemonProtectedCredentialEnrollmentSession { #[cfg(all(target_os = \"macos\", target_arch = \"aarch64\", feature = \"desktop-protected\"))] qualification: Option<crate::protected_activation::control_v3::initial_exchange::VerifiedQualificationAdmission> }",
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
        "#[cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))] fn verify_and_retain_qualification_admission(installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, verifier: &mut runne_native_qualification::QualificationAdmissionVerifier, admission: runne_native_qualification::PendingQualificationAdmission, members: qualification_fence::QualificationAdmissionMembers, now_unix_seconds: u64) -> Result<VerifiedQualificationAdmission, LaunchAuthorityError> { todo!() }",
    )
    .unwrap();
    source == DAEMON_SOURCE
        && item.attrs == expected.attrs
        && item.vis == expected.vis
        && signatures_match(&item.sig, &expected.sig)
}

pub fn exact_test_retention_helper(source: &str, item: &syn::ItemFn) -> bool {
    let expected: syn::ItemFn = syn::parse_str(
        "#[cfg(all(test, target_os = \"macos\", target_arch = \"aarch64\"))] pub(crate) fn verify_and_retain_qualification_admission_for_test(installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, verifier: &mut runne_native_qualification::QualificationAdmissionVerifier, admission: runne_native_qualification::PendingQualificationAdmission, members: qualification_fence::QualificationAdmissionMembers, now_unix_seconds: u64) -> Result<VerifiedQualificationAdmission, LaunchAuthorityError> { todo!() }",
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
        "#[cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))] enum InitialQualificationFrame { Legacy(Zeroizing<Vec<u8>>), Verified(VerifiedQualificationAdmission), }",
    )
    .unwrap();
    source == DAEMON_SOURCE
        && item.attrs == expected.attrs
        && item.ident == expected.ident
        && item.vis == expected.vis
        && item.generics == expected.generics
        && item.variants == expected.variants
}
