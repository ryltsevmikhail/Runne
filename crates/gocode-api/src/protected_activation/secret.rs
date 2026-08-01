/// A one-launch memory-only secret transported only over the inherited channel.
#[derive(Clone)]
pub struct LaunchSecret(Zeroizing<[u8; 32]>);

impl LaunchSecret {
    /// Creates a non-zero launch secret.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, LaunchAuthorityError> {
        if bytes == [0; 32] {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Derives role-separated keys without exposing the raw secret.
    #[must_use]
    pub fn derive_keys(&self) -> ProtectedActivationKeys {
        ProtectedActivationKeys {
            bootstrap: Zeroizing::new(derive_key(&self.0, BOOTSTRAP_DOMAIN)),
            readiness: Zeroizing::new(derive_key(&self.0, READINESS_DOMAIN)),
            renewal: Zeroizing::new(derive_key(&self.0, RENEW_DOMAIN)),
            shutdown: Zeroizing::new(derive_key(&self.0, SHUTDOWN_DOMAIN)),
        }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for LaunchSecret {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.as_ref().ct_eq(other.0.as_ref()))
    }
}

impl Eq for LaunchSecret {}

/// Role-separated activation keys retained only by native desktop and daemon.
#[derive(Clone)]
pub struct ProtectedActivationKeys {
    bootstrap: Zeroizing<[u8; 32]>,
    readiness: Zeroizing<[u8; 32]>,
    renewal: Zeroizing<[u8; 32]>,
    shutdown: Zeroizing<[u8; 32]>,
}

/// Raw activation-key copies exposed only to test-support leak audits.
///
/// The production build does not contain this type or its constructor.
#[cfg(feature = "test-support")]
pub struct ProtectedActivationKeyMaterialForTest {
    bootstrap: Zeroizing<[u8; 32]>,
    readiness: Zeroizing<[u8; 32]>,
    renewal: Zeroizing<[u8; 32]>,
    shutdown: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "test-support")]
impl ProtectedActivationKeyMaterialForTest {
    #[doc(hidden)]
    #[must_use]
    pub fn into_values(self) -> [Zeroizing<[u8; 32]>; 4] {
        [self.bootstrap, self.readiness, self.renewal, self.shutdown]
    }
}

impl ProtectedActivationKeys {
    /// Copies the one-time HTTP bootstrap key into another zeroizing owner.
    #[must_use]
    pub fn bootstrap_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.bootstrap)
    }

    /// Zeroizes the launch-only HTTP bootstrap key after the one-time native
    /// profile has taken ownership of its copy.
    pub fn forget_bootstrap_key(&mut self) {
        self.bootstrap.zeroize();
    }

    fn readiness_key(&self) -> &[u8; 32] {
        &self.readiness
    }

    fn renewal_key_ref(&self) -> &[u8; 32] {
        &self.renewal
    }

    fn shutdown_key_ref(&self) -> &[u8; 32] {
        &self.shutdown
    }

    /// Copies the protected renewal key for the owned control-channel endpoint.
    #[must_use]
    pub fn renewal_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.renewal)
    }

    /// Copies the protected shutdown key for the owned control-channel endpoint.
    #[must_use]
    pub fn shutdown_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.shutdown)
    }

    /// Copies every role-separated key for test-only forbidden-sink audits.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_material(&self) -> ProtectedActivationKeyMaterialForTest {
        ProtectedActivationKeyMaterialForTest {
            bootstrap: Zeroizing::new(*self.bootstrap),
            readiness: Zeroizing::new(*self.readiness),
            renewal: Zeroizing::new(*self.renewal),
            shutdown: Zeroizing::new(*self.shutdown),
        }
    }
}
