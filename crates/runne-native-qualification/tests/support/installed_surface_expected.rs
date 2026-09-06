pub fn exact_reviewed_facts_method(method: &syn::ImplItemFn) -> bool {
    let expected = match method.sig.ident.to_string().as_str() {
        "from_revalidated" => {
            "pub(in crate::updater_metadata) fn from_revalidated(value: &VerifiedDaemonNativeEnrollmentPrepare) -> Option<Self> {}"
        }
        "for_connected_relay_test" => {
            "pub(crate) const fn for_connected_relay_test(release: [u8; 32]) -> Self {}"
        }
        "desktop" => "pub const fn desktop(&self) -> [u8; 32] {}",
        "writer" => "pub const fn writer(&self) -> [u8; 32] {}",
        "daemon" => "pub const fn daemon(&self) -> [u8; 32] {}",
        "credential_service" => "pub const fn credential_service(&self) -> Option<[u8; 32]> {}",
        "runtime_credential_service_configuration" => {
            "pub fn runtime_credential_service_configuration(&self) -> Option<runne_macos_xpc::CredentialServiceEndpointConfiguration> {}"
        }
        "writer_credential_service_configuration" => {
            "pub fn writer_credential_service_configuration(&self) -> Option<runne_macos_xpc::CredentialServiceEndpointConfiguration> {}"
        }
        "contract" => "pub const fn contract(&self) -> [u8; 32] {}",
        "desktop_start" => "pub const fn desktop_start(&self) -> [u8; 32] {}",
        "release" => "pub const fn release(&self) -> [u8; 32] {}",
        "candidate_source" => "pub const fn candidate_source(&self) -> [u8; 32] {}",
        "target_manifest" => "pub const fn target_manifest(&self) -> [u8; 32] {}",
        "qualification" => "pub const fn qualification(&self) -> [u8; 32] {}",
        "installed_generation" => "pub const fn installed_generation(&self) -> u64 {}",
        "write_signed_release_metadata" => {
            "pub fn write_signed_release_metadata(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {}"
        }
        _ => return false,
    };
    exact_method(method, expected)
}

fn exact_method(actual: &syn::ImplItemFn, expected: &str) -> bool {
    let expected: syn::ImplItemFn = syn::parse_str(expected).unwrap();
    let mut actual_signature = actual.sig.clone();
    let mut expected_signature = expected.sig;
    actual_signature.inputs.pop_punct();
    expected_signature.inputs.pop_punct();
    actual.vis == expected.vis && actual_signature == expected_signature
}
