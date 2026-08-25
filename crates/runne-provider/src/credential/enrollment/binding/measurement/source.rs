use std::{fmt, sync::Arc};

use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, authority::EnrollmentAuthoritySeal,
};

macro_rules! measured_source {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            digest: CredentialBindingDigest,
            seal: Arc<EnrollmentAuthoritySeal>,
        }

        impl $name {
            pub(crate) fn issue(
                seal: Arc<EnrollmentAuthoritySeal>,
                bytes: [u8; 32],
            ) -> Result<Self, CredentialEnrollmentError> {
                Ok(Self {
                    digest: CredentialBindingDigest::from_measured(bytes)?,
                    seal,
                })
            }

            /// Returns the canonical stored binding digest.
            pub const fn digest(&self) -> CredentialBindingDigest {
                self.digest
            }

            pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
                Arc::ptr_eq(&self.seal, seal)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest)
                    .finish()
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.digest == other.digest && Arc::ptr_eq(&self.seal, &other.seal)
            }
        }

        impl Eq for $name {}
    };
}

measured_source!(
    CandidateSourceIdentity,
    "Measured candidate source identity."
);

impl CandidateSourceIdentity {
    pub(crate) fn authority_seal(&self) -> &Arc<EnrollmentAuthoritySeal> {
        &self.seal
    }
}
measured_source!(ReleaseManifestDigest, "Measured release manifest digest.");
measured_source!(
    DesktopExecutableIdentity,
    "Measured desktop executable identity."
);
measured_source!(
    WriterExecutableIdentity,
    "Measured writer executable identity."
);
measured_source!(
    ReaderExecutableIdentity,
    "Measured reader executable identity."
);
measured_source!(ContractBundleDigest, "Measured contract bundle digest.");
measured_source!(DaemonAuthorityId, "Measured daemon authority identity.");
measured_source!(ProtectedSessionId, "Measured protected-session identity.");
measured_source!(WriterLaunchId, "Measured writer launch identity.");
measured_source!(
    WriterProcessStartIdentity,
    "OS-native writer process start identity."
);
measured_source!(
    WriterProcessHandleIdentity,
    "Retained writer process handle identity."
);
measured_source!(
    BrokerChannelBinding,
    "Measured inherited broker channel binding."
);
measured_source!(
    ContinuationBindingDigest,
    "Accepted continuation authority digest."
);
