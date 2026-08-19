use std::sync::{Mutex, MutexGuard};

use core_foundation::base::ToVoid as _;
use core_foundation::number::CFNumber;
use security_framework::item::{ItemSearchOptions, KeyClass, Location, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::item::{
    kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
    kSecAttrKeyTypeECSECPrimeRandom,
};

const SEAL_KEY_LABEL_PREFIX: &str = "dev.runne.security-transaction-seal.v1.";
const SEAL_PREIMAGE_DOMAIN: &[u8] = b"runne/security-transaction-seal/v1\0";
static SECURITY_PROFILE_PROCESS_LOCK: Mutex<()> = Mutex::new(());

/// Opaque signature bytes produced by the profile's Secure Enclave key.
pub struct SecurityTransactionSeal(Vec<u8>);

impl SecurityTransactionSeal {
    /// Returns the DER-encoded ECDSA signature for durable storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Holds the same-process and cross-process security-state serialization locks.
///
/// The native private key remains private to this module. This guard is bound to
/// exactly one profile digest and cannot be reused for another profile.
pub struct SecurityProfileProcessLock {
    profile_identity_digest: [u8; 32],
    _same_process: MutexGuard<'static, ()>,
    _cross_process: ProviderCredentialProcessLock,
    private_key: SecKey,
}

impl SecurityProfileProcessLock {
    /// Acquires the profile/process lock and loads or creates its permanent
    /// Secure Enclave P-256 signing key.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the profile is invalid, a lock cannot be
    /// acquired, or the Keychain/Secure Enclave cannot provide the key.
    pub fn acquire(profile_identity_digest: [u8; 32]) -> Result<Self, KeychainAclError> {
        if profile_identity_digest == [0; 32] {
            return Err(KeychainAclError::InvalidProfileBinding);
        }
        let same_process = SECURITY_PROFILE_PROCESS_LOCK
            .lock()
            .map_err(|_| KeychainAclError::OperationFailed)?;
        let cross_process = ProviderCredentialProcessLock::acquire()?;
        let private_key = load_or_create_seal_key(profile_identity_digest)?;
        Ok(Self {
            profile_identity_digest,
            _same_process: same_process,
            _cross_process: cross_process,
            private_key,
        })
    }

    /// Returns whether this guard is bound to the supplied profile digest.
    #[must_use]
    pub fn matches(&self, profile_identity_digest: [u8; 32]) -> bool {
        self.profile_identity_digest == profile_identity_digest
    }

    /// Signs the fixed, domain-separated security transaction preimage.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a mismatched profile, an unavailable native
    /// signer, or a malformed native signature.
    pub fn seal(
        &self,
        profile_identity_digest: [u8; 32],
        database_identity: [u8; 32],
        generation: u64,
        transaction_digest: [u8; 32],
        previous_anchor_digest: [u8; 32],
    ) -> Result<SecurityTransactionSeal, KeychainAclError> {
        let preimage = self.preimage(
            profile_identity_digest,
            database_identity,
            generation,
            transaction_digest,
            previous_anchor_digest,
        )?;
        let signature = self
            .private_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, &preimage)
            .map_err(|_| KeychainAclError::OperationFailed)?;
        if !valid_der_signature(&signature) {
            return Err(KeychainAclError::InvalidSeal);
        }
        Ok(SecurityTransactionSeal(signature))
    }

    /// Verifies a persisted signature against the profile's public key.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a mismatched profile, malformed signature,
    /// unavailable key, or failed signature verification.
    pub fn verify(
        &self,
        profile_identity_digest: [u8; 32],
        database_identity: [u8; 32],
        generation: u64,
        transaction_digest: [u8; 32],
        previous_anchor_digest: [u8; 32],
        signature: &[u8],
    ) -> Result<(), KeychainAclError> {
        if !valid_der_signature(signature) {
            return Err(KeychainAclError::InvalidSeal);
        }
        let preimage = self.preimage(
            profile_identity_digest,
            database_identity,
            generation,
            transaction_digest,
            previous_anchor_digest,
        )?;
        let public_key = self
            .private_key
            .public_key()
            .ok_or(KeychainAclError::OperationFailed)?;
        match public_key.verify_signature(
            Algorithm::ECDSASignatureMessageX962SHA256,
            &preimage,
            signature,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(KeychainAclError::InvalidSeal),
            Err(_) => Err(KeychainAclError::OperationFailed),
        }
    }

    fn preimage(
        &self,
        profile_identity_digest: [u8; 32],
        database_identity: [u8; 32],
        generation: u64,
        transaction_digest: [u8; 32],
        previous_anchor_digest: [u8; 32],
    ) -> Result<Vec<u8>, KeychainAclError> {
        if profile_identity_digest != self.profile_identity_digest {
            return Err(KeychainAclError::InvalidProfileBinding);
        }
        let mut preimage = Vec::with_capacity(SEAL_PREIMAGE_DOMAIN.len() + 136);
        preimage.extend_from_slice(SEAL_PREIMAGE_DOMAIN);
        preimage.extend_from_slice(&profile_identity_digest);
        preimage.extend_from_slice(&database_identity);
        preimage.extend_from_slice(&generation.to_be_bytes());
        preimage.extend_from_slice(&transaction_digest);
        preimage.extend_from_slice(&previous_anchor_digest);
        Ok(preimage)
    }
}

fn load_or_create_seal_key(profile_identity_digest: [u8; 32]) -> Result<SecKey, KeychainAclError> {
    let label = seal_key_label(profile_identity_digest);
    if let Some(key) = find_seal_key(&label)? {
        return validate_seal_key(key);
    }
    let mut options = GenerateKeyOptions::default();
    #[allow(deprecated)]
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_label(label)
        .set_token(Token::SecureEnclave)
        .set_location(Location::DataProtectionKeychain);
    let key = SecKey::new(&options).map_err(|_| KeychainAclError::OperationFailed)?;
    validate_seal_key(key)
}

fn find_seal_key(label: &str) -> Result<Option<SecKey>, KeychainAclError> {
    let mut options = ItemSearchOptions::new();
    options
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .limit(2_i64);
    match options.search() {
        Ok(mut matches) => match matches.len() {
            0 => Ok(None),
            1 => match matches.pop() {
                Some(SearchResult::Ref(Reference::Key(key))) => Ok(Some(key)),
                _ => Err(KeychainAclError::OperationFailed),
            },
            _ => Err(KeychainAclError::OperationFailed),
        },
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        Err(_) => Err(KeychainAclError::OperationFailed),
    }
}

fn validate_seal_key(key: SecKey) -> Result<SecKey, KeychainAclError> {
    let attributes = key.attributes();
    let token = attributes
        .find(unsafe { kSecAttrTokenID }.to_void())
        .map(|value| unsafe { CFString::wrap_under_get_rule(value.cast()) });
    let key_type = attributes
        .find(unsafe { kSecAttrKeyType }.to_void())
        .map(|value| unsafe { CFString::wrap_under_get_rule(value.cast()) });
    let key_size = attributes
        .find(unsafe { kSecAttrKeySizeInBits }.to_void())
        .map(|value| unsafe { CFNumber::wrap_under_get_rule(value.cast()) })
        .and_then(|size| size.to_i32());
    let expected_token = unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) };
    let expected_type = unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) };
    if token.as_ref() != Some(&expected_token)
        || key_type.as_ref() != Some(&expected_type)
        || key_size != Some(256)
    {
        return Err(KeychainAclError::OperationFailed);
    }
    Ok(key)
}

fn seal_key_label(profile_identity_digest: [u8; 32]) -> String {
    let mut label = String::with_capacity(SEAL_KEY_LABEL_PREFIX.len() + 64);
    label.push_str(SEAL_KEY_LABEL_PREFIX);
    for byte in profile_identity_digest {
        use std::fmt::Write as _;
        let _ = write!(label, "{byte:02x}");
    }
    label
}

fn valid_der_signature(signature: &[u8]) -> bool {
    if !(1..=80).contains(&signature.len()) || signature.first() != Some(&0x30) {
        return false;
    }
    let Some(&length) = signature.get(1) else {
        return false;
    };
    if length & 0x80 != 0 || usize::from(length) + 2 != signature.len() {
        return false;
    }
    let Some(next) = valid_der_integer(signature, 2) else {
        return false;
    };
    valid_der_integer(signature, next) == Some(signature.len())
}

fn valid_der_integer(signature: &[u8], offset: usize) -> Option<usize> {
    if signature.get(offset) != Some(&0x02) {
        return None;
    }
    let length = usize::from(*signature.get(offset + 1)?);
    if !(1..=33).contains(&length) {
        return None;
    }
    let value = signature.get(offset + 2..offset + 2 + length)?;
    if value[0] & 0x80 != 0 || (value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0) {
        return None;
    }
    Some(offset + 2 + length)
}
