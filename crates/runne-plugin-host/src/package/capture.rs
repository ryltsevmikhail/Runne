fn validate_declared_files(
    manifest: &ParsedManifest,
    files: &[PluginPackageFile],
) -> Result<(), PluginPackageCaptureError> {
    if manifest.files.len() != files.len() {
        return Err(PluginPackageCaptureError::FileTableMismatch);
    }
    for (declared, captured) in manifest.files.iter().zip(files) {
        if declared.path.as_str() != captured.path.as_ref()
            || declared.kind != captured.kind
            || declared.size != captured.bytes.len() as u64
            || declared.digest != digest(FILE_DIGEST_DOMAIN, &captured.bytes)
        {
            return Err(PluginPackageCaptureError::FileTableMismatch);
        }
    }
    let entrypoint = files
        .iter()
        .find(|file| file.path.as_ref() == manifest.entrypoint.as_str());
    if !matches!(entrypoint, Some(file) if file.kind == PluginPackageFileKind::Executable) {
        return Err(PluginPackageCaptureError::EntrypointMismatch);
    }
    let file_table = canonical_file_table(files);
    if digest(FILE_TABLE_DIGEST_DOMAIN, &file_table) != manifest.file_table_digest {
        return Err(PluginPackageCaptureError::FileTableMismatch);
    }
    Ok(())
}

/// Kind of a captured logical package file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginPackageFileKind {
    /// Non-executable immutable resource.
    Data,
    /// Verified executable entrypoint or helper.
    Executable,
}

/// One immutable file accepted by the ADR-0015 package capture boundary.
#[derive(PartialEq, Eq)]
pub struct PluginPackageFile {
    path: Box<str>,
    kind: PluginPackageFileKind,
    bytes: Box<[u8]>,
}

impl PluginPackageFile {
    /// Validates the portable logical path and takes bounded ownership of bytes.
    pub fn try_new(
        path: String,
        kind: PluginPackageFileKind,
        bytes: Vec<u8>,
    ) -> Result<Self, PluginPackageCaptureError> {
        validate_package_path(&path)?;
        if bytes.len() > MAX_PACKAGE_FILE_BYTES {
            return Err(PluginPackageCaptureError::TooLarge);
        }
        Ok(Self {
            path: path.into_boxed_str(),
            kind,
            bytes: bytes.into_boxed_slice(),
        })
    }

    /// Canonical portable path.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Declared executable/data kind.
    pub const fn kind(&self) -> PluginPackageFileKind {
        self.kind
    }
    /// Exact immutable captured bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn validate_package_path(path: &str) -> Result<(), PluginPackageCaptureError> {
    if path.is_empty()
        || path.len() > MAX_PACKAGE_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.contains(':')
        || !path.is_ascii()
        || path.eq_ignore_ascii_case("gocode-plugin.toml")
    {
        return Err(PluginPackageCaptureError::InvalidPath);
    }
    let mut segment_count = 0usize;
    for segment in path.split('/') {
        segment_count += 1;
        if segment_count > MAX_PACKAGE_PATH_DEPTH {
            return Err(PluginPackageCaptureError::InvalidPath);
        }
        if segment.is_empty()
            || segment.len() > 128
            || matches!(segment, "." | "..")
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || !matches!(segment.as_bytes().first(), Some(byte) if byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
            || !matches!(segment.as_bytes().last(), Some(byte) if byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        {
            return Err(PluginPackageCaptureError::InvalidPath);
        }
        let base = segment.split('.').next().unwrap_or_default();
        let upper = base.to_ascii_uppercase();
        if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (upper.len() == 4
                && (upper.starts_with("COM") || upper.starts_with("LPT"))
                && matches!(upper.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(PluginPackageCaptureError::InvalidPath);
        }
    }
    Ok(())
}

/// Rejection at the bounded owned-content capture boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginPackageCaptureError {
    /// At least one caller-owned component exceeds the trusted capture bound.
    TooLarge,
    /// A logical package path violates ADR-0015 portable path rules.
    InvalidPath,
    /// The manifest could not be parsed under the pinned normalized grammar.
    InvalidManifest,
    /// The protocol profile was not a complete canonical ADR-0015 tuple.
    InvalidProfile,
    /// The manifest profile reference differs from the complete supplied tuple.
    ProfileDeclarationMismatch,
    /// Declared and captured file tables differ or contain a case-fold alias.
    FileTableMismatch,
    /// The selected entrypoint is absent or not executable.
    EntrypointMismatch,
    /// Two captured logical paths are identical or ASCII-case aliases.
    DuplicatePath,
}

/// Opaque, retained evidence captured from owned package content.
#[derive(PartialEq, Eq)]
pub struct PluginPackageSource {
    content: PluginPackageContent,
    package_digest: PluginDigest,
    manifest_digest: PluginDigest,
    entrypoint_digest: PluginDigest,
    declared_class: PluginClass,
    protocol_profile_digest: PluginDigest,
    trust_binding_digest: PluginDigest,
}

impl fmt::Debug for PluginPackageSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginPackageSource")
            .field("package_digest", &self.package_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("entrypoint_digest", &self.entrypoint_digest)
            .field("declared_class", &self.declared_class)
            .field("protocol_profile_digest", &self.protocol_profile_digest)
            .field("trust_binding_digest", &self.trust_binding_digest)
            .finish()
    }
}

/// Captures package evidence by hashing and retaining owned source bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct PluginPackageCapture;

impl PluginPackageCapture {
    /// Consumes source content and computes digests bound to its retained bytes.
    pub fn capture(
        content: PluginPackageContent,
        declared_class: PluginClass,
    ) -> PluginPackageSource {
        let manifest = parse_manifest(&content.manifest_bytes)
            .expect("PluginPackageContent validates the pinned manifest grammar");
        let manifest_bytes = canonical_manifest_bytes(&manifest);
        let manifest_digest = digest(MANIFEST_DIGEST_DOMAIN, &manifest_bytes);
        let entrypoint_digest = content
            .files
            .iter()
            .find(|file| file.path.as_ref() == manifest.entrypoint.as_str())
            .map(|file| digest(FILE_DIGEST_DOMAIN, &file.bytes))
            .expect("PluginPackageContent validates the executable entrypoint");
        let file_table_bytes = canonical_file_table(&content.files);
        let file_table_digest = digest(FILE_TABLE_DIGEST_DOMAIN, &file_table_bytes);
        let package_digest = package_digest(manifest_digest, file_table_digest);
        let protocol_profile_digest = PluginDigest::from_bytes(
            protocol_profile_digest(&content.protocol_profile).into_bytes(),
        );
        let trust_binding_digest =
            digest(TRUST_BINDING_DIGEST_DOMAIN, &content.trust_binding_bytes);

        PluginPackageSource {
            content,
            package_digest,
            manifest_digest,
            entrypoint_digest,
            declared_class,
            protocol_profile_digest,
            trust_binding_digest,
        }
    }
}

impl PluginPackageSource {
    /// Returns the computed package digest for comparison or audit.
    pub const fn package_digest(&self) -> PluginDigest {
        self.package_digest
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> PluginDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    PluginDigest::from_bytes(hasher.finalize().into())
}

fn package_digest(manifest: PluginDigest, table: PluginDigest) -> PluginDigest {
    let mut hasher = Sha256::new();
    hasher.update(PACKAGE_DIGEST_DOMAIN);
    hasher.update(MANIFEST_CONTRACT_DIGEST);
    hasher.update(manifest.as_bytes());
    hasher.update(table.as_bytes());
    PluginDigest::from_bytes(hasher.finalize().into())
}

fn canonical_manifest_bytes(parsed: &ParsedManifest) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.write_map_header(9);
    enc.write_unsigned(1);
    enc.write_text_string(parsed.package_id.as_str());
    enc.write_unsigned(2);
    enc.write_text_string(parsed.package_version.as_str());
    enc.write_unsigned(3);
    enc.write_text_string(parsed.host_identity.as_str());
    enc.write_unsigned(4);
    enc.write_text_string(parsed.plugin_identity.as_str());
    enc.write_unsigned(5);
    enc.write_text_string(parsed.target_identity.as_str());
    enc.write_unsigned(6);
    enc.write_text_string(parsed.entrypoint.as_str());
    enc.write_unsigned(7);
    enc.write_byte_string(parsed.file_table_digest.as_bytes());
    enc.write_unsigned(8);
    enc.write_array_header(2);
    enc.write_text_string(parsed.protocol_profile_id.as_str());
    enc.write_byte_string(parsed.protocol_profile_digest.as_bytes());
    enc.write_unsigned(9);
    enc.write_array_header(parsed.files.len() as u64);
    for file in &parsed.files {
        encode_file_table_entry(&mut enc, &file.path, file.kind, file.size, file.digest);
    }
    enc.into_bytes()
}

fn canonical_file_table(files: &[PluginPackageFile]) -> Vec<u8> {
    let mut enc = CborEncoder::new();
    enc.write_array_header(files.len() as u64);
    for file in files {
        encode_file_table_entry(
            &mut enc,
            &file.path,
            file.kind,
            file.bytes.len() as u64,
            digest(FILE_DIGEST_DOMAIN, &file.bytes),
        );
    }
    enc.into_bytes()
}

fn encode_file_table_entry(
    enc: &mut CborEncoder,
    path: &str,
    kind: PluginPackageFileKind,
    size: u64,
    file_digest: PluginDigest,
) {
    enc.write_map_header(4);
    enc.write_unsigned(1);
    enc.write_text_string(path);
    enc.write_unsigned(2);
    enc.write_text_string(match kind {
        PluginPackageFileKind::Data => "data",
        PluginPackageFileKind::Executable => "executable",
    });
    enc.write_unsigned(3);
    enc.write_unsigned(size);
    enc.write_unsigned(4);
    enc.write_byte_string(file_digest.as_bytes());
}
