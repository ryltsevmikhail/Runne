use super::model::UpdateTrustRootV2;

/// Opaque updater trust root compiled into every native consumer binary.
pub struct CompiledUpdateTrustRootV2 {
    trust: UpdateTrustRootV2,
}

impl CompiledUpdateTrustRootV2 {
    /// Loads all compiled public trust keys, otherwise fails closed.
    #[must_use]
    pub fn load() -> Option<Self> {
        let values = CompiledUpdateTrustRootValues {
            root_a_id: option_env!("RUNNE_UPDATE_ROOT_A_ID"),
            root_b_id: option_env!("RUNNE_UPDATE_ROOT_B_ID"),
            root_c_id: option_env!("RUNNE_UPDATE_ROOT_C_ID"),
            timestamp_id: option_env!("RUNNE_UPDATE_TIMESTAMP_ID"),
            snapshot_id: option_env!("RUNNE_UPDATE_SNAPSHOT_ID"),
            root_a_hex: option_env!("RUNNE_UPDATE_ROOT_A_HEX"),
            root_b_hex: option_env!("RUNNE_UPDATE_ROOT_B_HEX"),
            root_c_hex: option_env!("RUNNE_UPDATE_ROOT_C_HEX"),
            timestamp_hex: option_env!("RUNNE_UPDATE_TIMESTAMP_HEX"),
            snapshot_hex: option_env!("RUNNE_UPDATE_SNAPSHOT_HEX"),
        };
        Self::from_values(&values).or_else(Self::local_test_trust)
    }

    /// Transfers the verified opaque trust root to an existing updater composition root.
    #[must_use]
    pub fn into_trust_root(self) -> UpdateTrustRootV2 {
        self.trust
    }

    fn from_values(values: &CompiledUpdateTrustRootValues) -> Option<Self> {
        let values = values.required()?;
        Some(Self {
            trust: UpdateTrustRootV2::from_keys(
                [
                    (values.root_a_id, key(values.root_a_hex)?),
                    (values.root_b_id, key(values.root_b_hex)?),
                    (values.root_c_id, key(values.root_c_hex)?),
                ],
                (values.timestamp_id, key(values.timestamp_hex)?),
                (values.snapshot_id, key(values.snapshot_hex)?),
            ),
        })
    }

    #[cfg(feature = "test-support")]
    fn local_test_trust() -> Option<Self> {
        use ed25519_dalek::SigningKey;

        crate::test_support::local_native_enrollment_enabled().then(|| {
            let keys = [11_u8, 12, 13, 14, 15].map(|byte| {
                SigningKey::from_bytes(&[byte; 32])
                    .verifying_key()
                    .to_bytes()
            });
            Self {
                trust: UpdateTrustRootV2::from_keys(
                    [
                        ("root-a", keys[0]),
                        ("root-b", keys[1]),
                        ("root-c", keys[2]),
                    ],
                    ("timestamp", keys[3]),
                    ("snapshot", keys[4]),
                ),
            }
        })
    }

    #[cfg(not(feature = "test-support"))]
    const fn local_test_trust() -> Option<Self> {
        None
    }
}

fn key(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

struct CompiledUpdateTrustRootValues {
    root_a_id: Option<&'static str>,
    root_b_id: Option<&'static str>,
    root_c_id: Option<&'static str>,
    timestamp_id: Option<&'static str>,
    snapshot_id: Option<&'static str>,
    root_a_hex: Option<&'static str>,
    root_b_hex: Option<&'static str>,
    root_c_hex: Option<&'static str>,
    timestamp_hex: Option<&'static str>,
    snapshot_hex: Option<&'static str>,
}

impl CompiledUpdateTrustRootValues {
    fn required(&self) -> Option<RequiredCompiledUpdateTrustRootValues> {
        Some(RequiredCompiledUpdateTrustRootValues {
            root_a_id: self.root_a_id?,
            root_b_id: self.root_b_id?,
            root_c_id: self.root_c_id?,
            timestamp_id: self.timestamp_id?,
            snapshot_id: self.snapshot_id?,
            root_a_hex: self.root_a_hex?,
            root_b_hex: self.root_b_hex?,
            root_c_hex: self.root_c_hex?,
            timestamp_hex: self.timestamp_hex?,
            snapshot_hex: self.snapshot_hex?,
        })
    }
}

struct RequiredCompiledUpdateTrustRootValues {
    root_a_id: &'static str,
    root_b_id: &'static str,
    root_c_id: &'static str,
    timestamp_id: &'static str,
    snapshot_id: &'static str,
    root_a_hex: &'static str,
    root_b_hex: &'static str,
    root_c_hex: &'static str,
    timestamp_hex: &'static str,
    snapshot_hex: &'static str,
}

#[cfg(test)]
#[path = "compiled_trust_tests.rs"]
mod tests;
