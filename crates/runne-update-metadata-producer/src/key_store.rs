use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

#[cfg(all(target_os = "macos", debug_assertions, feature = "dev-keyset-init"))]
use crate::input::UpdatePublicKeyManifest;
use crate::issuer::ProducerError;

const SERVICE: &str = "runne.desktop.update-metadata/2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeySlot {
    RootA,
    RootB,
    RootC,
    Snapshot,
    Timestamp,
}

impl KeySlot {
    pub const ALL: [Self; 5] = [
        Self::RootA,
        Self::RootB,
        Self::RootC,
        Self::Snapshot,
        Self::Timestamp,
    ];

    #[must_use]
    pub const fn account(self) -> &'static str {
        match self {
            Self::RootA => "root-a",
            Self::RootB => "root-b",
            Self::RootC => "root-c",
            Self::Snapshot => "snapshot",
            Self::Timestamp => "timestamp",
        }
    }

    #[must_use]
    pub const fn key_id(self) -> &'static str {
        match self {
            Self::RootA => "runne-update-root-a-v2",
            Self::RootB => "runne-update-root-b-v2",
            Self::RootC => "runne-update-root-c-v2",
            Self::Snapshot => "runne-update-snapshot-v2",
            Self::Timestamp => "runne-update-timestamp-v2",
        }
    }
}

pub trait UpdateSigningKeyStore {
    fn public_key(&self, slot: KeySlot) -> Result<[u8; 32], ProducerError>;
    fn sign(&self, slot: KeySlot, bytes: &[u8]) -> Result<[u8; 64], ProducerError>;
}

#[cfg(target_os = "macos")]
pub struct MacKeychainStore {
    keychain: security_framework::os::macos::keychain::SecKeychain,
}

#[cfg(target_os = "macos")]
impl MacKeychainStore {
    #[cfg(all(debug_assertions, feature = "dev-keyset-init"))]
    pub fn initialize(path: &std::path::Path) -> Result<UpdatePublicKeyManifest, ProducerError> {
        use rand::RngCore as _;
        require_stable_operator_identity()?;
        let store = Self::open(path)?;
        for slot in KeySlot::ALL {
            if store
                .keychain
                .find_generic_password(SERVICE, slot.account())
                .is_ok()
            {
                return Err(ProducerError::KeyStore);
            }
            let mut seed = Zeroizing::new([0_u8; 32]);
            rand::rngs::OsRng.fill_bytes(seed.as_mut());
            store
                .keychain
                .set_generic_password(SERVICE, slot.account(), seed.as_ref())
                .map_err(|_| ProducerError::KeyStore)?;
        }
        store.manifest()
    }

    pub fn open(path: &std::path::Path) -> Result<Self, ProducerError> {
        if !path.is_absolute() {
            return Err(ProducerError::KeyStore);
        }
        let keychain = security_framework::os::macos::keychain::SecKeychain::open(path)
            .map_err(|_| ProducerError::KeyStore)?;
        Ok(Self { keychain })
    }

    fn seed(&self, slot: KeySlot) -> Result<Zeroizing<Vec<u8>>, ProducerError> {
        let (bytes, _) = self
            .keychain
            .find_generic_password(SERVICE, slot.account())
            .map_err(|_| ProducerError::KeyStore)?;
        let bytes = bytes.to_vec();
        if bytes.len() != 32 {
            return Err(ProducerError::KeyStore);
        }
        Ok(Zeroizing::new(bytes))
    }

    #[cfg(all(debug_assertions, feature = "dev-keyset-init"))]
    fn manifest(self) -> Result<UpdatePublicKeyManifest, ProducerError> {
        Ok(UpdatePublicKeyManifest {
            schema_version: 1,
            root_a_id: KeySlot::RootA.key_id().into(),
            root_a_hex: hex::encode(self.public_key(KeySlot::RootA)?),
            root_b_id: KeySlot::RootB.key_id().into(),
            root_b_hex: hex::encode(self.public_key(KeySlot::RootB)?),
            root_c_id: KeySlot::RootC.key_id().into(),
            root_c_hex: hex::encode(self.public_key(KeySlot::RootC)?),
            snapshot_id: KeySlot::Snapshot.key_id().into(),
            snapshot_hex: hex::encode(self.public_key(KeySlot::Snapshot)?),
            timestamp_id: KeySlot::Timestamp.key_id().into(),
            timestamp_hex: hex::encode(self.public_key(KeySlot::Timestamp)?),
        })
    }
}

#[cfg(all(target_os = "macos", debug_assertions, feature = "dev-keyset-init"))]
fn require_stable_operator_identity() -> Result<(), ProducerError> {
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

    const REQUIREMENT: &str = "identifier \"com.runne.update-metadata-producer\" and anchor apple generic and certificate leaf[subject.OU] = \"758F9Z45SR\"";
    let requirement: SecRequirement = REQUIREMENT.parse().map_err(|_| ProducerError::KeyStore)?;
    let code = SecCode::for_self(Flags::NONE).map_err(|_| ProducerError::KeyStore)?;
    code.check_validity(Flags::STRICT_VALIDATE, &requirement)
        .map_err(|_| ProducerError::KeyStore)
}

#[cfg(target_os = "macos")]
impl UpdateSigningKeyStore for MacKeychainStore {
    fn public_key(&self, slot: KeySlot) -> Result<[u8; 32], ProducerError> {
        let seed = self.seed(slot)?;
        let value: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| ProducerError::KeyStore)?;
        Ok(SigningKey::from_bytes(&value).verifying_key().to_bytes())
    }

    fn sign(&self, slot: KeySlot, bytes: &[u8]) -> Result<[u8; 64], ProducerError> {
        let seed = self.seed(slot)?;
        let value: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| ProducerError::KeyStore)?;
        Ok(SigningKey::from_bytes(&value).sign(bytes).to_bytes())
    }
}

#[cfg(not(target_os = "macos"))]
pub struct UnavailableKeyStore;

#[cfg(not(target_os = "macos"))]
impl UpdateSigningKeyStore for UnavailableKeyStore {
    fn public_key(&self, _slot: KeySlot) -> Result<[u8; 32], ProducerError> {
        Err(ProducerError::KeyStore)
    }

    fn sign(&self, _slot: KeySlot, _bytes: &[u8]) -> Result<[u8; 64], ProducerError> {
        Err(ProducerError::KeyStore)
    }
}
