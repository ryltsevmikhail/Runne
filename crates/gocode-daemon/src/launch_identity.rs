//! Fresh per-launch TLS and bootstrap identity.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Datelike, Duration, Utc};
use gocode_api::DaemonInstanceId;
use rand::{RngCore, rngs::OsRng};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};

/// Fresh, non-serializable identity for one daemon launch.
pub struct LaunchIdentity {
    certificate_der: Vec<u8>,
    certificate_sha256: [u8; 32],
    bootstrap_secret: [u8; 32],
    daemon_instance_id: DaemonInstanceId,
    launch_generation: u64,
    server_config: Arc<ServerConfig>,
}

impl Drop for LaunchIdentity {
    fn drop(&mut self) {
        self.bootstrap_secret.zeroize();
    }
}

impl LaunchIdentity {
    /// Creates one loopback-only TLS identity and bootstrap secret.
    pub fn generate(launch_generation: u64) -> Result<Self, LaunchIdentityError> {
        Self::generate_inner(launch_generation, None)
    }

    fn generate_inner(
        launch_generation: u64,
        marker_out: Option<&mut [u8; 32]>,
    ) -> Result<Self, LaunchIdentityError> {
        if launch_generation == 0 {
            return Err(LaunchIdentityError::InvalidGeneration);
        }
        let mut params =
            CertificateParams::new(Vec::new()).map_err(|_| LaunchIdentityError::Certificate)?;
        let now = Utc::now().date_naive();
        let expires = now + Duration::days(30);
        params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        params.not_after =
            rcgen::date_time_ymd(expires.year(), expires.month() as u8, expires.day() as u8);
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
        if let Some(marker) = marker_out {
            *marker = private_key_marker(&private_key_der);
        }
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
    /// Returns a non-secret marker used to prove bootstrap secrets are distinct.
    pub fn bootstrap_secret_marker(&self) -> [u8; 32] {
        Sha256::digest(self.bootstrap_secret).into()
    }
    /// Copies the launch bootstrap secret only into the in-process session service.
    pub(crate) const fn bootstrap_secret(&self) -> [u8; 32] {
        self.bootstrap_secret
    }
    #[allow(dead_code)]
    pub(crate) fn write_bootstrap_secret(&self, path: &std::path::Path) -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&self.bootstrap_secret)?;
        file.sync_all()
    }

    #[cfg(test)]
    pub(crate) fn generate_with_private_key_marker_for_test(
        launch_generation: u64,
    ) -> Result<(Self, [u8; 32]), LaunchIdentityError> {
        let mut marker = [0; 32];
        let identity = Self::generate_inner(launch_generation, Some(&mut marker))?;
        Ok((identity, marker))
    }
}

fn private_key_marker(key_der: &[u8]) -> [u8; 32] {
    key_der[..32]
        .try_into()
        .expect("P-256 PKCS#8 key is at least 32 bytes")
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
