use std::fs;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use sha2::{Digest, Sha256};

pub fn certificate_der() -> Vec<u8> {
    let mut parameters = CertificateParams::new(Vec::new()).expect("certificate parameters");
    parameters.subject_alt_names = vec![SanType::IpAddress(std::net::IpAddr::V4(
        std::net::Ipv4Addr::LOCALHOST,
    ))];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    parameters
        .self_signed(&key)
        .expect("certificate")
        .der()
        .to_vec()
}

pub fn ordered_capability_digest(capabilities: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"runne/local-runtime/capability-digest/v1\0");
    hasher.update(u32::try_from(capabilities.len()).unwrap().to_be_bytes());
    for capability in capabilities {
        hasher.update(u32::try_from(capability.len()).unwrap().to_be_bytes());
        hasher.update(capability.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(unix)]
pub fn secure(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure file");
}

#[cfg(not(unix))]
pub const fn secure(_: &std::path::Path) {}
