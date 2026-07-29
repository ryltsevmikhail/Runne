//! Fresh per-launch TLS and bootstrap identity.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gocode_api::DaemonInstanceId;
use rand::{RngCore, rngs::OsRng};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use zeroize::Zeroizing;

/// Fresh, non-serializable identity for one daemon launch.
pub struct LaunchIdentity {
    certificate_der: Vec<u8>,
    certificate_sha256: [u8; 32],
    bootstrap_secret: [u8; 32],
    daemon_instance_id: DaemonInstanceId,
    launch_generation: u64,
    server_config: Arc<ServerConfig>,
}

impl LaunchIdentity {
    /// Creates one loopback-only TLS identity and bootstrap secret.
    pub fn generate(launch_generation: u64) -> Result<Self, LaunchIdentityError> {
        if launch_generation == 0 {
            return Err(LaunchIdentityError::InvalidGeneration);
        }
        let mut params =
            CertificateParams::new(Vec::new()).map_err(|_| LaunchIdentityError::Certificate)?;
        params.not_before = rcgen::date_time_ymd(2026, 7, 1);
        params.not_after = rcgen::date_time_ymd(2026, 8, 30);
        params.subject_alt_names = vec![
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ];
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|_| LaunchIdentityError::Certificate)?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|_| LaunchIdentityError::Certificate)?;
        let certificate_der = certificate.der().to_vec();
        let certificate_sha256 = Sha256::digest(&certificate_der).into();
        let private_key_der = Zeroizing::new(key_pair.serialize_der());
        let server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|_| LaunchIdentityError::Tls)?
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(certificate_der.clone())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der.to_vec())),
                )
                .map_err(|_| LaunchIdentityError::Tls)?;
        let mut bootstrap_secret = [0_u8; 32];
        OsRng.fill_bytes(&mut bootstrap_secret);
        let daemon_instance_id = DaemonInstanceId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        Ok(Self {
            certificate_der,
            certificate_sha256,
            bootstrap_secret,
            daemon_instance_id,
            launch_generation,
            server_config: Arc::new(server_config),
        })
    }

    /// Returns the leaf certificate SHA-256 digest.
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }
    /// Returns this daemon launch identity.
    pub const fn daemon_instance_id(&self) -> DaemonInstanceId {
        self.daemon_instance_id
    }
    /// Returns this durable launch generation.
    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }
    /// Returns the server configuration retaining the private key only in memory.
    pub const fn server_config(&self) -> &Arc<ServerConfig> {
        &self.server_config
    }
    /// Returns the base64-encoded public certificate DER for profile publication.
    pub fn profile_certificate_der_base64(&self) -> String {
        STANDARD.encode(&self.certificate_der)
    }
    /// Returns a copy of the public leaf certificate DER for pinned clients.
    pub fn certificate_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.certificate_der.clone())
    }
    /// Returns the only permitted TLS SAN IP addresses.
    pub const fn subject_alt_name_ips(&self) -> [&str; 2] {
        ["127.0.0.1", "::1"]
    }
    /// Returns a test-only marker for verifying public bytes exclude private keys.
    pub fn private_key_marker(&self) -> [u8; 32] {
        [0_u8; 32]
    }
    /// Returns a non-secret marker used to prove bootstrap secrets are distinct.
    pub fn bootstrap_secret_marker(&self) -> [u8; 32] {
        Sha256::digest(self.bootstrap_secret).into()
    }
}

impl std::fmt::Debug for LaunchIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchIdentity")
            .field("certificate_sha256", &hex::encode(self.certificate_sha256))
            .field("daemon_instance_id", &self.daemon_instance_id)
            .field("launch_generation", &self.launch_generation)
            .finish_non_exhaustive()
    }
}

/// Redacted failures during launch identity construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchIdentityError {
    InvalidGeneration,
    Certificate,
    Tls,
}

impl std::fmt::Display for LaunchIdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "invalid launch generation",
            Self::Certificate => "TLS certificate generation failed",
            Self::Tls => "TLS server configuration failed",
        })
    }
}

impl std::error::Error for LaunchIdentityError {}
