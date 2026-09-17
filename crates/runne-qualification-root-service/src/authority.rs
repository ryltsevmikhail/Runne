use ed25519_dalek::SigningKey;
use runne_qualification_bootstrap_policy::QualificationBootstrapPolicy;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result, executable::AdmittedExecutable, protected_file::ProtectedFile};

const SEED_PATH: &str =
    "/private/var/db/gocode/sourcecraft-native-qualification/context-authority-ed25519.seed";
const EVIDENCE_POLICY_PATH: &str =
    "/private/etc/gocode/sourcecraft-native-qualification/policy.json";

pub struct Authority {
    seed: ProtectedFile,
    evidence: ProtectedFile,
    key: SigningKey,
}

impl Authority {
    pub fn load(
        policy: &QualificationBootstrapPolicy,
        executable: &AdmittedExecutable,
    ) -> Result<Self> {
        if !runne_native_qualification::qualification_bootstrap_compiled_authorities_match(
            policy.context_public_key(),
            policy.context_key_id(),
            policy.fault_public_key(),
            policy.fault_key_id(),
        ) {
            return Err(Error);
        }
        executable.revalidate(policy)?;
        let seed = ProtectedFile::load(SEED_PATH, 32, true)?;
        let evidence = ProtectedFile::load(EVIDENCE_POLICY_PATH, 65_536, false)?;
        let bytes = seed.bytes()?;
        if bytes.len() != 32 {
            return Err(Error);
        }
        let mut key_bytes = Zeroizing::new([0; 32]);
        key_bytes.copy_from_slice(&bytes);
        let key = SigningKey::from_bytes(&key_bytes);
        let value = Self {
            seed,
            evidence,
            key,
        };
        value.revalidate(policy)?;
        Ok(value)
    }

    pub fn revalidate(&self, policy: &QualificationBootstrapPolicy) -> Result<()> {
        self.seed.revalidate()?;
        self.evidence.revalidate()?;
        if !runne_native_qualification::qualification_bootstrap_compiled_authorities_match(
            policy.context_public_key(),
            policy.context_key_id(),
            policy.fault_public_key(),
            policy.fault_key_id(),
        ) || self.key.verifying_key().to_bytes() != policy.context_public_key()
        {
            return Err(Error);
        }
        let evidence: EvidencePolicy =
            serde_json::from_slice(&self.evidence.bytes()?).map_err(|_| Error)?;
        let public_key: [u8; 32] = hex::decode(&evidence.evidence_authority.public_key)
            .map_err(|_| Error)?
            .try_into()
            .map_err(|_| Error)?;
        if evidence.schema_version != "runne/sourcecraft-native-qualification-policy/v1"
            || hex::encode(public_key) != evidence.evidence_authority.public_key
            || hex::encode(Sha256::digest(public_key)) != evidence.evidence_authority.key_id
            || !distinct_authorities(
                public_key,
                &evidence.evidence_authority.key_id,
                [
                    (policy.context_public_key(), policy.context_key_id()),
                    (policy.fault_public_key(), policy.fault_key_id()),
                ],
            )
        {
            return Err(Error);
        }
        Ok(())
    }

    pub const fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

// Only public authority pins are selected from the separately protected evidence
// policy. This does not replace its qualification workflow validator.
#[derive(Deserialize)]
struct EvidencePolicy {
    schema_version: String,
    evidence_authority: EvidenceAuthority,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceAuthority {
    public_key: String,
    key_id: String,
}

fn distinct_authorities(key: [u8; 32], key_id: &str, pins: [([u8; 32], [u8; 32]); 2]) -> bool {
    pins.into_iter()
        .all(|(pin, id)| key != pin && key_id != hex::encode(id))
}

#[cfg(test)]
mod tests {
    use super::distinct_authorities;

    #[test]
    fn evidence_cannot_share_context_or_fault_key_or_key_id() {
        let pins = [([1; 32], [2; 32]), ([3; 32], [4; 32])];
        assert!(distinct_authorities([5; 32], &hex::encode([6; 32]), pins));
        for (key, id) in pins {
            assert!(!distinct_authorities(key, &hex::encode([6; 32]), pins));
            assert!(!distinct_authorities([5; 32], &hex::encode(id), pins));
        }
    }
}
