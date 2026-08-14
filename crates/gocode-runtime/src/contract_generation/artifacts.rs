/// Writes all runtime-owned contract artifacts under `output`.
pub fn generate_ui_contract(output: &Path) -> Result<(), ContractGenerationError> {
    let artifacts = generated_artifacts()?;
    for (relative_path, bytes) in artifacts {
        let path = output.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)?;
    }
    Ok(())
}

/// Generates to an isolated temporary directory and byte-compares every
/// authoritative artifact without writing the checked-in target.
pub fn check_ui_contract(target: &Path) -> Result<(), ContractGenerationError> {
    let temporary = tempfile::tempdir()?;
    generate_ui_contract(temporary.path())?;
    let expected_paths = GENERATED_ARTIFACT_PATHS
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let mut checked_in_paths = contract_files(target)?;
    checked_in_paths.retain(|path| path != Path::new("package.json"));
    if checked_in_paths != expected_paths {
        return Err(ContractGenerationError::ArtifactSetMismatch);
    }
    for relative_path in GENERATED_ARTIFACT_PATHS {
        let generated = fs::read(temporary.path().join(relative_path))?;
        let checked_in = fs::read(target.join(relative_path))
            .map_err(|_| ContractGenerationError::ByteMismatch((*relative_path).into()))?;
        if generated != checked_in {
            return Err(ContractGenerationError::ByteMismatch(
                (*relative_path).into(),
            ));
        }
    }
    Ok(())
}

fn contract_files(root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    fn visit(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(current)? {
            let path = entry?.path();
            if path.is_dir() {
                visit(root, &path, files)?;
            } else {
                files.push(
                    path.strip_prefix(root)
                        .expect("visited contract path remains below root")
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn generated_artifacts() -> Result<BTreeMap<&'static str, Vec<u8>>, ContractGenerationError> {
    let mut artifacts = BTreeMap::from([
        (
            "golden/local-session-v2.json",
            canonical_json(&local_session_golden())?,
        ),
        (
            "golden/operational-telemetry.json",
            canonical_json(&operational_telemetry_golden())?,
        ),
        (
            "golden/project-workspace.json",
            canonical_json(&project_workspace_golden())?,
        ),
        (
            "golden/replay-retention-gap-v2.json",
            canonical_json(&replay_retention_baseline_v2_golden())?,
        ),
        (
            "golden/replay-retention-gap.json",
            canonical_json(&replay_retention_baseline_golden())?,
        ),
        (
            "golden/replay-resume-v2.json",
            canonical_json(&replay_resume_from_baseline_golden())?,
        ),
        (
            "golden/replay-conversation.json",
            canonical_json(&replay_conversation_golden())?,
        ),
        (
            "golden/replay-taskrun.json",
            canonical_json(&replay_taskrun_golden())?,
        ),
        (
            "golden/sse-delivery.json",
            canonical_json(&sse_delivery_golden())?,
        ),
        ("openapi.json", canonical_json(&openapi())?),
        (
            "schemas/local-runtime-profile-v3.schema.json",
            canonical_json(&local_runtime_profile_schema())?,
        ),
        (
            "schemas/local-session-v2.schema.json",
            canonical_json(&local_session_schema())?,
        ),
        (
            "schemas/operational-telemetry-v1.schema.json",
            canonical_json(&operational_telemetry_schema())?,
        ),
        (
            "schemas/project-workspace-v2.schema.json",
            canonical_json(&project_workspace_schema())?,
        ),
        (
            "schemas/replay-v1.schema.json",
            canonical_json(&replay_schema())?,
        ),
        ("schemas/sse-v1.schema.json", canonical_json(&sse_schema())?),
    ]);

    let artifact_digests = artifacts
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path,
                "sha256": hex::encode(Sha256::digest(bytes)),
            })
        })
        .collect::<Vec<_>>();
    let bundle = json!({
        "apiProfileId": BUNDLE_ID,
        "artifactDigests": artifact_digests,
        "capabilityCatalog": RUNTIME_CAPABILITY_CATALOG,
        "generatorSchemaVersion": GENERATOR_SCHEMA_VERSION,
        "publishedCapabilities": PUBLISHED_RUNTIME_CAPABILITIES,
        "transportProfileId": TRANSPORT_PROFILE_ID,
    });
    let bundle_bytes = canonical_json(&bundle)?;
    let bundle_digest = hex::encode(Sha256::digest(&bundle_bytes));
    artifacts.insert("bundle.json", bundle_bytes);
    artifacts.insert("bundle.sha256", format!("{bundle_digest}\n").into_bytes());
    Ok(artifacts)
}
