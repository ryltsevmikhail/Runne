const WRITER_STARTUP_KDF: &[u8] = b"gocode/provider-credential-broker/writer-startup-kdf/v1";
const WRITER_STARTUP_CHALLENGE: &[u8] =
    b"gocode/provider-credential-broker/writer-startup-challenge/v1";
const WRITER_STARTUP_RESPONSE: &[u8] =
    b"gocode/provider-credential-broker/writer-startup-response/v1";
const WRITER_STARTUP_PAYLOAD_BYTES: usize = 160;

/// One-writer startup proof key, scoped to its nonce and exact measured tuple.
pub struct CredentialBrokerWriterStartupAuthenticator {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 32],
    release: [u8; 32],
    channel: [u8; 32],
    publication_key: [u8; 32],
}

impl CredentialBrokerTransferAuthenticator {
    /// Derives a distinct one-writer key without exposing this authenticator's keys.
    #[must_use]
    pub fn derive_writer_startup_authenticator(
        &self,
        nonce: [u8; 32],
        release: [u8; 32],
        channel: [u8; 32],
        publication_key: [u8; 32],
    ) -> Option<CredentialBrokerWriterStartupAuthenticator> {
        if [nonce, release, channel, publication_key].contains(&[0; 32]) {
            return None;
        }
        let mut context = [0; 128];
        context[..32].copy_from_slice(&nonce);
        context[32..64].copy_from_slice(&release);
        context[64..96].copy_from_slice(&channel);
        context[96..].copy_from_slice(&publication_key);
        Some(CredentialBrokerWriterStartupAuthenticator {
            key: Zeroizing::new(authenticated_mac(
                &self.daemon_transfer_key,
                WRITER_STARTUP_KDF,
                &context,
            )),
            nonce,
            release,
            channel,
            publication_key,
        })
    }
}

impl CredentialBrokerWriterStartupAuthenticator {
    /// Adopts only the narrow startup key and its fixed daemon-owned context.
    pub fn from_handoff_payload(payload: &[u8; WRITER_STARTUP_PAYLOAD_BYTES]) -> Option<Self> {
        let key = payload[..32].try_into().ok()?;
        let release = payload[32..64].try_into().ok()?;
        let channel = payload[64..96].try_into().ok()?;
        let publication_key = payload[96..128].try_into().ok()?;
        let nonce = payload[128..].try_into().ok()?;
        if [key, release, channel, publication_key, nonce].contains(&[0; 32]) {
            return None;
        }
        Some(Self {
            key: Zeroizing::new(key),
            nonce,
            release,
            channel,
            publication_key,
        })
    }

    /// Encodes only the derived writer-scoped key, never protected activation keys.
    #[must_use]
    pub fn handoff_payload(&self) -> Zeroizing<[u8; WRITER_STARTUP_PAYLOAD_BYTES]> {
        let mut payload = Zeroizing::new([0; WRITER_STARTUP_PAYLOAD_BYTES]);
        payload[..32].copy_from_slice(&self.key[..]);
        payload[32..64].copy_from_slice(&self.release);
        payload[64..96].copy_from_slice(&self.channel);
        payload[96..128].copy_from_slice(&self.publication_key);
        payload[128..].copy_from_slice(&self.nonce);
        payload
    }

    #[must_use]
    pub const fn release(&self) -> [u8; 32] {
        self.release
    }
    #[must_use]
    pub const fn channel(&self) -> [u8; 32] {
        self.channel
    }
    #[must_use]
    pub const fn publication_key(&self) -> [u8; 32] {
        self.publication_key
    }
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn authenticate_daemon_proof(&self, record: &[u8]) -> [u8; 32] {
        authenticated_mac(&self.key, WRITER_STARTUP_CHALLENGE, record)
    }
    #[must_use]
    pub fn verifies_daemon_proof(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_daemon_proof(record).ct_eq(proof))
    }
    pub fn authenticate_writer_proof(&self, record: &[u8]) -> [u8; 32] {
        authenticated_mac(&self.key, WRITER_STARTUP_RESPONSE, record)
    }
    #[must_use]
    pub fn verifies_writer_proof(&self, record: &[u8], proof: &[u8; 32]) -> bool {
        bool::from(self.authenticate_writer_proof(record).ct_eq(proof))
    }

    pub(crate) fn is_derived_for(
        &self,
        transfer: &CredentialBrokerTransferAuthenticator,
        release: [u8; 32],
        channel: [u8; 32],
        publication_key: [u8; 32],
    ) -> bool {
        self.release == release
            && self.channel == channel
            && self.publication_key == publication_key
            && transfer
                .derive_writer_startup_authenticator(self.nonce, release, channel, publication_key)
                .is_some_and(|expected| bool::from(expected.key[..].ct_eq(&self.key[..])))
    }
}

impl std::fmt::Debug for CredentialBrokerWriterStartupAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialBrokerWriterStartupAuthenticator(<redacted>)")
    }
}
