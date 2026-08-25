impl UpdateRootRoleV2 {
    #[must_use]
    pub fn from_trust(trust: &UpdateTrustRootV2, version: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            version,
            threshold: 2,
            key_ids: trust
                .root_keys
                .iter()
                .map(|key| key.key_id.clone())
                .collect(),
        }
    }
}

fn trusted_key((key_id, public_key): (&str, [u8; 32])) -> UpdateTrustedKeyV2 {
    UpdateTrustedKeyV2 {
        key_id: key_id.to_owned(),
        public_key,
    }
}

fn root_matches(root: &UpdateRootRoleV2, trust: &UpdateTrustRootV2) -> bool {
    *root == UpdateRootRoleV2::from_trust(trust, root.version)
}

fn target_matches(target: &UpdateTargetV2, binding: &UpdateTargetV2Binding<'_>) -> bool {
    target.product_id == binding.product_id
        && target.platform == binding.platform
        && target.arch == binding.arch
        && target.min_os == binding.min_os
        && target.profile_id == binding.profile_id
        && target.bundle_sha256 == binding.bundle_sha256
        && target.runtime_version == binding.runtime_version
        && target.runtime_digest == binding.runtime_digest
        && target.channel == binding.channel
}

fn verify_quorum<T: Serialize>(
    signatures: &[UpdateSignatureV2],
    keys: &[UpdateTrustedKeyV2],
    value: &T,
    threshold: usize,
) -> Result<(), ()> {
    if signatures.len() > MAX_SIGNATURES {
        return Err(());
    }
    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    let mut verified = HashSet::new();
    for signature in signatures {
        let Some(key) = keys.iter().find(|key| key.key_id == signature.key_id) else {
            continue;
        };
        if verify_bytes(&key.public_key, &bytes, &signature.signature).is_ok() {
            verified.insert(signature.key_id.as_str());
        }
    }
    (verified.len() >= threshold).then_some(()).ok_or(())
}

fn verify_single<T: Serialize>(
    encoded: &str,
    key: &UpdateTrustedKeyV2,
    value: &T,
) -> Result<(), ()> {
    verify_bytes(
        &key.public_key,
        &serde_json::to_vec(value).map_err(|_| ())?,
        encoded,
    )
}

fn verify_bytes(public_key: &[u8; 32], bytes: &[u8], encoded: &str) -> Result<(), ()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| ())?;
    let signature = hex::decode(encoded).map_err(|_| ())?;
    let signature = Signature::from_slice(&signature).map_err(|_| ())?;
    key.verify(bytes, &signature).map_err(|_| ())
}
