/// Owned plugin content consumed by the capture boundary.
#[derive(PartialEq, Eq)]
pub struct PluginPackageContent {
    manifest_bytes: Box<[u8]>,
    files: Box<[PluginPackageFile]>,
    protocol_profile: ProtocolSupportProfile,
    trust_binding_bytes: Box<[u8]>,
}

impl PluginPackageContent {
    /// Takes bounded ownership of all package bytes before capture.
    pub fn try_new(
        package_bytes: Vec<u8>,
        manifest_bytes: Vec<u8>,
        entrypoint_bytes: Vec<u8>,
        protocol_profile_bytes: Vec<u8>,
        trust_binding_bytes: Vec<u8>,
    ) -> Result<Self, PluginPackageCaptureError> {
        if package_bytes.len() > MAX_PACKAGE_FILE_BYTES
            || entrypoint_bytes.len() > MAX_PACKAGE_FILE_BYTES
            || manifest_bytes.len() > MAX_MANIFEST_BYTES
            || protocol_profile_bytes.len() > MAX_PROFILE_OR_TRUST_BYTES
            || trust_binding_bytes.len() > MAX_PROFILE_OR_TRUST_BYTES
        {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        let protocol_profile = parse_profile(&protocol_profile_bytes)
            .map_err(|_| PluginPackageCaptureError::InvalidProfile)?;
        let manifest = parse_manifest(&manifest_bytes)
            .map_err(|_| PluginPackageCaptureError::InvalidManifest)?;
        let files = vec![
            PluginPackageFile::try_new(
                manifest.entrypoint.as_str().to_owned(),
                PluginPackageFileKind::Executable,
                entrypoint_bytes,
            )?,
            PluginPackageFile::try_new(
                "package".to_owned(),
                PluginPackageFileKind::Data,
                package_bytes,
            )?,
        ];
        Self::try_from_files(manifest_bytes, files, protocol_profile, trust_binding_bytes)
    }

    /// Captures an arbitrary complete logical file set after exact manifest
    /// declaration equality and trusted bounds checks.
    pub fn try_from_files(
        manifest_bytes: Vec<u8>,
        mut files: Vec<PluginPackageFile>,
        protocol_profile: ProtocolSupportProfile,
        trust_binding_bytes: Vec<u8>,
    ) -> Result<Self, PluginPackageCaptureError> {
        if manifest_bytes.len() > MAX_MANIFEST_BYTES
            || protocol_profile.profile_bytes().len() > MAX_PROFILE_OR_TRUST_BYTES
            || trust_binding_bytes.len() > MAX_PROFILE_OR_TRUST_BYTES
            || files.is_empty()
            || files.len() > MAX_PACKAGE_FILES
        {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        if files.windows(2).any(|pair| pair[0].path >= pair[1].path)
            || files.iter().enumerate().any(|(index, file)| {
                files[index + 1..]
                    .iter()
                    .any(|other| file.path.eq_ignore_ascii_case(&other.path))
            })
        {
            return Err(PluginPackageCaptureError::DuplicatePath);
        }
        let retained_file_bytes = files
            .iter()
            .try_fold(0usize, |total, file| total.checked_add(file.bytes.len()));
        let total = retained_file_bytes
            .and_then(|value| value.checked_add(manifest_bytes.len()))
            .and_then(|value| value.checked_add(protocol_profile.profile_bytes().len()))
            .and_then(|value| value.checked_add(trust_binding_bytes.len()))
            .ok_or(PluginPackageCaptureError::TooLarge)?;
        if total > MAX_PACKAGE_RETAINED_BYTES {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        let manifest = parse_manifest(&manifest_bytes)
            .map_err(|_| PluginPackageCaptureError::InvalidManifest)?;
        if manifest.protocol_profile_id != protocol_profile.profile_id
            || manifest.protocol_profile_digest
                != PluginDigest::from_bytes(protocol_profile_digest(&protocol_profile).into_bytes())
        {
            return Err(PluginPackageCaptureError::ProfileDeclarationMismatch);
        }
        validate_declared_files(&manifest, &files)?;
        Ok(Self {
            manifest_bytes: manifest_bytes.into_boxed_slice(),
            files: files.into_boxed_slice(),
            protocol_profile,
            trust_binding_bytes: trust_binding_bytes.into_boxed_slice(),
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        package_bytes: Vec<u8>,
        mut manifest_bytes: Vec<u8>,
        entrypoint_bytes: Vec<u8>,
        mut protocol_profile_bytes: Vec<u8>,
        trust_binding_bytes: Vec<u8>,
    ) -> Self {
        if parse_profile(&protocol_profile_bytes).is_err() {
            protocol_profile_bytes = upgrade_legacy_test_profile(&protocol_profile_bytes);
        }
        if parse_manifest(&manifest_bytes).is_err() {
            manifest_bytes = upgrade_legacy_test_manifest(
                &manifest_bytes,
                &package_bytes,
                &entrypoint_bytes,
                &protocol_profile_bytes,
            );
        }
        Self::try_new(
            package_bytes,
            manifest_bytes,
            entrypoint_bytes,
            protocol_profile_bytes,
            trust_binding_bytes,
        )
        .expect("test package content must satisfy the production capture boundary")
    }
}

#[cfg(test)]
fn upgrade_legacy_test_manifest(
    manifest: &[u8],
    package: &[u8],
    entrypoint: &[u8],
    profile: &[u8],
) -> Vec<u8> {
    let text = core::str::from_utf8(manifest).expect("test manifest is UTF-8");
    let entrypoint_path = text
        .lines()
        .find_map(|line| line.strip_prefix("entrypoint="))
        .expect("test manifest carries an entrypoint");
    let mut files = vec![
        PluginPackageFile::try_new(
            entrypoint_path.to_owned(),
            PluginPackageFileKind::Executable,
            entrypoint.to_vec(),
        )
        .unwrap(),
        PluginPackageFile::try_new(
            "package".to_owned(),
            PluginPackageFileKind::Data,
            package.to_vec(),
        )
        .unwrap(),
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let table_digest = digest(FILE_TABLE_DIGEST_DOMAIN, &canonical_file_table(&files));
    let mut upgraded = text.trim_end().to_owned();
    upgraded.push('\n');
    upgraded.push_str("file_table_digest=");
    upgraded.push_str(&tagged_digest(table_digest));
    upgraded.push('\n');
    let profile = parse_profile(profile).expect("upgraded test profile is complete");
    upgraded.push_str("protocol_profile=");
    upgraded.push_str(profile.profile_id.as_str());
    upgraded.push('|');
    upgraded.push_str(&tagged_digest(PluginDigest::from_bytes(
        protocol_profile_digest(&profile).into_bytes(),
    )));
    upgraded.push('\n');
    for file in files {
        upgraded.push_str("file=");
        upgraded.push_str(file.path());
        upgraded.push('|');
        upgraded.push_str(match file.kind() {
            PluginPackageFileKind::Data => "data",
            PluginPackageFileKind::Executable => "executable",
        });
        upgraded.push('|');
        upgraded.push_str(&file.bytes().len().to_string());
        upgraded.push('|');
        upgraded.push_str(&tagged_digest(digest(FILE_DIGEST_DOMAIN, file.bytes())));
        upgraded.push('\n');
    }
    upgraded.into_bytes()
}

#[cfg(test)]
fn upgrade_legacy_test_profile(profile: &[u8]) -> Vec<u8> {
    let text = core::str::from_utf8(profile).expect("test profile is UTF-8");
    let profile_id = text
        .lines()
        .find_map(|line| line.strip_prefix("profile_id="))
        .expect("test profile carries an id");
    format!(
        "RUNNE_PLUGIN_PROFILE_V1\nprofile_id={profile_id}\nversion=1.0\nbootstrap_schema_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\nwire_contract_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222\nsession_schema_bundle_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333\nfeatures=bootstrap-v2\nbounds_profile_digest=sha256:4444444444444444444444444444444444444444444444444444444444444444\n"
    )
    .into_bytes()
}

#[cfg(test)]
fn tagged_digest(digest: PluginDigest) -> String {
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in digest.as_bytes() {
        use core::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}
