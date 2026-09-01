use runne_api::CompiledUpdateTrustRootV2;

fn read(relative: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap()
}

#[test]
fn compiled_trust_root_is_owned_by_api_and_loaded_only_at_compile_time() {
    let load: fn() -> Option<CompiledUpdateTrustRootV2> = CompiledUpdateTrustRootV2::load;
    let _ = load;

    let source =
        read("src/provider_credential_enrollment/signed_installed_release/compiled_trust.rs");
    assert_eq!(source.matches("option_env!(\"RUNNE_UPDATE_").count(), 10);
    for forbidden in ["std::env", "env::var", "env::var_os", "pub fn from_values"] {
        assert!(
            !source.contains(forbidden),
            "forbidden trust source: {forbidden}"
        );
    }
}
