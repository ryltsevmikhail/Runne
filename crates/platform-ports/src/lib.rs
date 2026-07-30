//! Domain-neutral native capability traits.

pub mod desktop;

use std::fmt;

/// Every platform capability the host can query.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum CapabilityId {
    DirectoryPicker,
    SecureStore,
    ExternalEditor,
    RuntimeLifecycle,
    Notifications,
    DeepLinks,
    Camera,
    BiometricReauth,
    NetworkState,
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Typed result of a capability query — never panics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityAvailability {
    Available,
    Unavailable { reason: String },
    PermissionRequired,
}

/// Answers capability queries for one platform target.
pub trait PlatformCapabilityProvider {
    fn availability(&self, id: CapabilityId) -> CapabilityAvailability;
}

/// Typed wrapper: holds a capability ID + its availability.
/// Ensures capability checks happen before use.
#[derive(Clone, Debug)]
pub struct CheckedCapability {
    pub id: CapabilityId,
    pub availability: CapabilityAvailability,
}

impl CheckedCapability {
    /// Returns the capability if available, otherwise an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the capability is `Unavailable` or requires
    /// `PermissionRequired`.
    pub fn require_available(&self) -> Result<CapabilityId, String> {
        match &self.availability {
            CapabilityAvailability::Available => Ok(self.id),
            CapabilityAvailability::PermissionRequired => {
                Err(format!("{} requires user permission", self.id))
            }
            CapabilityAvailability::Unavailable { reason } => {
                Err(format!("{} is unavailable: {reason}", self.id))
            }
        }
    }
}

/// Fixed capability matrix for a platform profile.
pub struct PlatformMatrix {
    entries: Vec<(CapabilityId, CapabilityAvailability)>,
}

impl PlatformMatrix {
    #[must_use]
    pub fn desktop() -> Self {
        use CapabilityAvailability::{Available, Unavailable};
        use CapabilityId::{
            BiometricReauth, Camera, DeepLinks, DirectoryPicker, ExternalEditor, NetworkState,
            Notifications, RuntimeLifecycle, SecureStore,
        };
        Self {
            entries: vec![
                (DirectoryPicker, Available),
                (SecureStore, Available),
                (ExternalEditor, Available),
                (
                    RuntimeLifecycle,
                    Unavailable {
                        reason:
                            "protected transport and production v2 integration are not implemented"
                                .into(),
                    },
                ),
                (Notifications, Available),
                (DeepLinks, Available),
                (
                    Camera,
                    Unavailable {
                        reason: "camera not available on desktop".into(),
                    },
                ),
                (
                    BiometricReauth,
                    Unavailable {
                        reason: "biometrics not available on desktop".into(),
                    },
                ),
                (NetworkState, Available),
            ],
        }
    }

    /// Mobile capability matrix — all entries default to `Unavailable`.
    ///
    /// iOS (aarch64-apple-ios) and Android (aarch64-linux-android)
    /// targets are not provisioned in CI. The Tauri plugin set
    /// (biometric, notification, barcode-scanner) is documented but
    /// not compile-linked. When native targets are provisioned, each
    /// capability should be promoted after a real compile+link+smoke.
    ///
    /// Status: **Hypothesis** — OQ-006.
    #[must_use]
    pub fn mobile() -> Self {
        use CapabilityAvailability::Unavailable;
        use CapabilityId::{
            BiometricReauth, Camera, DeepLinks, DirectoryPicker, ExternalEditor, NetworkState,
            Notifications, RuntimeLifecycle, SecureStore,
        };
        Self {
            entries: vec![
                (
                    DirectoryPicker,
                    Unavailable {
                        reason: "mobile sandbox restricts directory browsing".into(),
                    },
                ),
                (
                    SecureStore,
                    Unavailable {
                        reason: "iOS Keychain/Android Keystore not compile-linked".into(),
                    },
                ),
                (
                    ExternalEditor,
                    Unavailable {
                        reason: "external editor not supported on mobile".into(),
                    },
                ),
                (
                    RuntimeLifecycle,
                    Unavailable {
                        reason: "runtime supervision is Phase 1".into(),
                    },
                ),
                (
                    Notifications,
                    Unavailable {
                        reason: "push notification plugin not provisioned".into(),
                    },
                ),
                (
                    DeepLinks,
                    Unavailable {
                        reason: "deep link handler not provisioned".into(),
                    },
                ),
                (
                    Camera,
                    Unavailable {
                        reason: "barcode-scanner plugin not provisioned".into(),
                    },
                ),
                (
                    BiometricReauth,
                    Unavailable {
                        reason: "biometric plugin not provisioned".into(),
                    },
                ),
                (
                    NetworkState,
                    Unavailable {
                        reason: "network plugin not provisioned".into(),
                    },
                ),
            ],
        }
    }
}

impl PlatformCapabilityProvider for PlatformMatrix {
    fn availability(&self, id: CapabilityId) -> CapabilityAvailability {
        self.entries.iter().find(|(cap, _)| *cap == id).map_or_else(
            || CapabilityAvailability::Unavailable {
                reason: "capability not in matrix".into(),
            },
            |(_, avail)| avail.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_matrix_distinguishes_desktop_from_mobile() {
        use CapabilityAvailability::*;
        use CapabilityId::*;

        let desktop = PlatformMatrix::desktop();
        let mobile = PlatformMatrix::mobile();

        assert_eq!(desktop.availability(DirectoryPicker), Available);
        assert_eq!(
            mobile.availability(DirectoryPicker),
            Unavailable {
                reason: "mobile sandbox restricts directory browsing".into()
            }
        );

        assert_eq!(desktop.availability(SecureStore), Available);
        assert!(matches!(
            mobile.availability(SecureStore),
            CapabilityAvailability::Unavailable { .. }
        ));

        assert_eq!(
            desktop.availability(Camera),
            Unavailable {
                reason: "camera not available on desktop".into()
            }
        );
        assert!(matches!(
            mobile.availability(Camera),
            CapabilityAvailability::Unavailable { .. }
        ));
    }

    #[test]
    fn unknown_capability_is_unavailable() {
        let desktop = PlatformMatrix::desktop();
        assert_eq!(
            desktop.availability(CapabilityId::RuntimeLifecycle),
            CapabilityAvailability::Unavailable {
                reason: "protected transport and production v2 integration are not implemented"
                    .into()
            }
        );
    }

    #[test]
    fn checked_capability_blocks_unavailable() {
        let matrix = PlatformMatrix::desktop();
        let cam = CheckedCapability {
            id: CapabilityId::Camera,
            availability: matrix.availability(CapabilityId::Camera),
        };
        assert!(cam.require_available().is_err());

        let dir = CheckedCapability {
            id: CapabilityId::DirectoryPicker,
            availability: matrix.availability(CapabilityId::DirectoryPicker),
        };
        assert!(dir.require_available().is_ok());
    }
}
