use std::fs::File;

use crate::packaged_writer_observation::artifact::RetainedArtifact;
use crate::packaged_writer_observation::package::{DirectorySnapshot, open_rooted_file};

use super::super::MacOsCredentialServicePackageObservationError;
use super::super::layout::{ENTRIES, ENTRY_COUNT, MAX_AGGREGATE_BYTES, executable};
use super::map;

pub(super) fn capture_entries(
    root: &File,
    root_identity: &DirectorySnapshot,
) -> Result<[RetainedArtifact; ENTRY_COUNT], MacOsCredentialServicePackageObservationError> {
    let (device, uid) = root_identity.device_uid();
    let mut opened = Vec::with_capacity(ENTRY_COUNT);
    let mut total = 0_u64;
    for entry in ENTRIES {
        let file = open_rooted_file(root, root_identity, entry.components).map_err(map)?;
        let snapshot =
            RetainedArtifact::preflight(&file, device, uid, executable(entry.role)).map_err(map)?;
        if snapshot.length() > entry.max_bytes {
            return Err(MacOsCredentialServicePackageObservationError::Rejected);
        }
        total = total
            .checked_add(snapshot.length())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        if total > MAX_AGGREGATE_BYTES {
            return Err(MacOsCredentialServicePackageObservationError::Rejected);
        }
        opened.push((file, snapshot));
    }
    opened
        .into_iter()
        .map(|(file, snapshot)| RetainedArtifact::capture_preflight(file, snapshot).map_err(map))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| MacOsCredentialServicePackageObservationError::Rejected)
}
