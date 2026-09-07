use std::path::{Path, PathBuf};

use super::MacOsCredentialServicePackageObservationError;

pub(super) const ENTRY_COUNT: usize = 10;
pub(super) const CANDIDATE_MAX_BYTES: u64 = 64 * 1024;
const LARGE_ENTRY_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_AGGREGATE_BYTES: u64 = 6 * LARGE_ENTRY_MAX_BYTES + 4 * CANDIDATE_MAX_BYTES;

#[derive(Clone, Copy)]
pub(super) enum ServiceRole {
    Desktop,
    Writer,
    Daemon,
    CredentialService,
    Resource,
}

#[derive(Clone, Copy)]
pub(super) struct Entry {
    pub(super) components: &'static [&'static str],
    pub(super) role: ServiceRole,
    pub(super) max_bytes: u64,
}

pub(super) const ENTRIES: [Entry; ENTRY_COUNT] = [
    Entry {
        components: &[
            "Contents",
            "Resources",
            "native-enrollment",
            "release-candidate-binding.json",
        ],
        role: ServiceRole::Resource,
        max_bytes: CANDIDATE_MAX_BYTES,
    },
    Entry {
        components: &["Contents", "MacOS", "runne-desktop"],
        role: ServiceRole::Desktop,
        max_bytes: LARGE_ENTRY_MAX_BYTES,
    },
    Entry {
        components: &["Contents", "MacOS", "runne"],
        role: ServiceRole::Writer,
        max_bytes: LARGE_ENTRY_MAX_BYTES,
    },
    Entry {
        components: &["Contents", "MacOS", "runned"],
        role: ServiceRole::Daemon,
        max_bytes: LARGE_ENTRY_MAX_BYTES,
    },
    Entry {
        components: &[
            "Contents",
            "Library",
            "Helpers",
            "RunneCredentialService.app",
            "Contents",
            "MacOS",
            "runne-credential-service",
        ],
        role: ServiceRole::CredentialService,
        max_bytes: LARGE_ENTRY_MAX_BYTES,
    },
    Entry {
        components: &[
            "Contents",
            "Library",
            "LaunchAgents",
            "com.runne.credential-service.plist",
        ],
        role: ServiceRole::Resource,
        max_bytes: CANDIDATE_MAX_BYTES,
    },
    Entry {
        components: &[
            "Contents",
            "Resources",
            "native-enrollment",
            "credential-service.entitlements.plist",
        ],
        role: ServiceRole::Resource,
        max_bytes: CANDIDATE_MAX_BYTES,
    },
    Entry {
        components: &[
            "Contents",
            "Library",
            "Helpers",
            "RunneCredentialService.app",
            "Contents",
            "embedded.provisionprofile",
        ],
        role: ServiceRole::Resource,
        max_bytes: LARGE_ENTRY_MAX_BYTES,
    },
    Entry {
        components: &[
            "Contents",
            "Resources",
            "native-enrollment",
            "xpc-protocol-v1.json",
        ],
        role: ServiceRole::Resource,
        max_bytes: CANDIDATE_MAX_BYTES,
    },
    Entry {
        components: &[
            "Contents",
            "Resources",
            "contracts",
            "gocode-ui-client-2",
            "bundle.json",
        ],
        role: ServiceRole::Resource,
        max_bytes: LARGE_ENTRY_MAX_BYTES,
    },
];

pub(super) fn application_from_service(
    service: &Path,
) -> Result<PathBuf, MacOsCredentialServicePackageObservationError> {
    let mut cursor = service;
    for expected in [
        "runne-credential-service",
        "MacOS",
        "Contents",
        "RunneCredentialService.app",
        "Helpers",
        "Library",
        "Contents",
        "Runne.app",
    ] {
        if cursor.file_name().is_none_or(|name| name != expected) {
            return Err(MacOsCredentialServicePackageObservationError::Rejected);
        }
        cursor = cursor
            .parent()
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
    }
    service
        .is_absolute()
        .then(|| cursor.join("Runne.app"))
        .ok_or(MacOsCredentialServicePackageObservationError::Rejected)
}

pub(super) fn rooted_path(application: &Path, entry: Entry) -> PathBuf {
    entry
        .components
        .iter()
        .fold(application.to_path_buf(), |path, component| {
            path.join(component)
        })
}

pub(super) const fn executable(role: ServiceRole) -> bool {
    matches!(
        role,
        ServiceRole::Desktop
            | ServiceRole::Writer
            | ServiceRole::Daemon
            | ServiceRole::CredentialService
    )
}
