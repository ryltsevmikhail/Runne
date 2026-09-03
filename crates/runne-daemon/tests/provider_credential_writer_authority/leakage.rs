pub(super) fn run() {
    super::harness::dispatch_scenarios(
        "real_process_sinks_and_receipts_contain_no_sensitive_material",
        &["leakage"],
        inner,
    );
}

fn inner(context: &super::support::InnerContext, _: &str) -> Result<(), &'static str> {
    context.run_positive_transcript(false)?;
    let secret = super::audit::secret_canary(context.root());
    let patterns = super::audit::sensitive_patterns(&secret);
    let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
    if super::audit::tree_contains(context.root(), &borrowed)? {
        return Err("sensitive-owned-tree");
    }
    super::audit::assert_completion_receipt_safe(context.runtime_root())?;
    assert_unqualified_profile()
}

fn assert_unqualified_profile() -> Result<(), &'static str> {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("repository-root")?;
    let profile = std::fs::read_to_string(
        repository.join("docs/profiles/native-credential-enrollment-v1.json"),
    )
    .map_err(|_| "native-profile")?;
    let profile: serde_json::Value =
        serde_json::from_str(&profile).map_err(|_| "native-profile-json")?;
    if profile
        .get("disposition")
        .and_then(serde_json::Value::as_str)
        != Some("unsupported")
        || profile
            .get("evidence_rows")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|rows| !rows.is_empty())
    {
        return Err("native-profile-qualified");
    }
    Ok(())
}
