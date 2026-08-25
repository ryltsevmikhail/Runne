use zeroize::Zeroizing;

use super::{
    ProviderCredentialAccessPolicy, ProviderCredentialMaterial, ProviderCredentialSourceRevision,
    SecureStoreError,
    source_update::{
        ProviderCredentialSourceSlot, ProviderCredentialSourceSlotBackend,
        commit_provider_credential_source_update, committed_provider_credential_source_slot,
        recover_provider_credential_source,
    },
};

#[derive(Default)]
struct FakeNativeSlots {
    slots: [Option<FakeNativeItem>; 2],
    fail_after: Option<usize>,
    mutations: usize,
    payload_reads: usize,
}

struct FakeNativeItem {
    metadata: Vec<u8>,
    encrypted_payload: Option<Zeroizing<Vec<u8>>>,
}

impl FakeNativeSlots {
    fn inject_after(&mut self, boundary: usize) {
        self.fail_after = Some(boundary);
        self.mutations = 0;
    }

    fn clear_failure(&mut self) {
        self.fail_after = None;
    }

    fn finish_mutation(&mut self) -> Result<(), SecureStoreError> {
        self.mutations += 1;
        if self.fail_after == Some(self.mutations) {
            Err(SecureStoreError::ProviderCredentialOperationFailed)
        } else {
            Ok(())
        }
    }

    fn occupied_slots(&self) -> usize {
        self.slots.iter().flatten().count()
    }
}

impl ProviderCredentialSourceSlotBackend for FakeNativeSlots {
    fn load_metadata(
        &mut self,
        slot: ProviderCredentialSourceSlot,
    ) -> Result<Option<Vec<u8>>, SecureStoreError> {
        Ok(self.slots[slot.index()]
            .as_ref()
            .map(|item| item.metadata.clone()))
    }

    fn load_encrypted_payload(
        &mut self,
        slot: ProviderCredentialSourceSlot,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        self.payload_reads += 1;
        Ok(self.slots[slot.index()]
            .as_ref()
            .and_then(|item| item.encrypted_payload.as_ref())
            .map(|payload| Zeroizing::new(payload.to_vec())))
    }

    fn create_incomplete(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        metadata: &[u8],
    ) -> Result<(), SecureStoreError> {
        if self.slots[slot.index()].is_some() {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        self.slots[slot.index()] = Some(FakeNativeItem {
            metadata: metadata.to_vec(),
            encrypted_payload: None,
        });
        self.finish_mutation()
    }

    fn write_encrypted_payload(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        payload: &[u8],
    ) -> Result<(), SecureStoreError> {
        self.slots[slot.index()]
            .as_mut()
            .ok_or(SecureStoreError::CorruptProviderCredential)?
            .encrypted_payload = Some(Zeroizing::new(payload.to_vec()));
        self.finish_mutation()
    }

    fn atomic_write_metadata(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        metadata: &[u8],
    ) -> Result<(), SecureStoreError> {
        self.slots[slot.index()]
            .as_mut()
            .ok_or(SecureStoreError::CorruptProviderCredential)?
            .metadata = metadata.to_vec();
        self.finish_mutation()
    }

    fn delete_slot(&mut self, slot: ProviderCredentialSourceSlot) -> Result<(), SecureStoreError> {
        self.slots[slot.index()] = None;
        self.finish_mutation()
    }
}

#[test]
fn every_source_update_boundary_recovers_one_committed_pair_and_replays_idempotently() {
    let executable = std::env::current_exe().unwrap();
    let access_path = unique_executable_copy(&executable);
    let access = ProviderCredentialAccessPolicy::new(&access_path, &access_path).unwrap();
    let old = ProviderCredentialMaterial::new(b"old-native-secret".to_vec()).unwrap();
    let replacement = ProviderCredentialMaterial::new(b"new-native-secret".to_vec()).unwrap();
    let old_revision = ProviderCredentialSourceRevision::new([0x31; 16]).unwrap();
    let new_revision = ProviderCredentialSourceRevision::new([0x42; 16]).unwrap();

    for boundary in 1..=5 {
        let mut backend = FakeNativeSlots::default();
        commit_provider_credential_source_update(
            &mut backend,
            &old,
            &access,
            [0xA5; 32],
            old_revision,
        )
        .unwrap();
        backend.inject_after(boundary);
        assert_eq!(
            commit_provider_credential_source_update(
                &mut backend,
                &replacement,
                &access,
                [0xA5; 32],
                new_revision,
            )
            .unwrap_err(),
            SecureStoreError::ProviderCredentialOperationFailed
        );
        backend.clear_failure();

        let recovered = recover_provider_credential_source(&mut backend, &access, [0xA5; 32])
            .unwrap()
            .unwrap();
        let expected = if boundary < 4 {
            b"old-native-secret".as_slice()
        } else {
            b"new-native-secret".as_slice()
        };
        let expected_revision = if boundary < 4 {
            old_revision
        } else {
            new_revision
        };
        assert_eq!(recovered.material().with_bytes(<[u8]>::to_vec), expected);
        assert_eq!(recovered.revision(), expected_revision);
        assert_eq!(backend.occupied_slots(), 1);

        commit_provider_credential_source_update(
            &mut backend,
            &replacement,
            &access,
            [0xA5; 32],
            new_revision,
        )
        .unwrap();
        let replay_mutations = backend.mutations;
        commit_provider_credential_source_update(
            &mut backend,
            &replacement,
            &access,
            [0xA5; 32],
            new_revision,
        )
        .unwrap();
        assert_eq!(backend.mutations, replay_mutations);
        let committed = recover_provider_credential_source(&mut backend, &access, [0xA5; 32])
            .unwrap()
            .unwrap();
        assert_eq!(committed.revision(), new_revision);
        assert_eq!(
            committed.material().with_bytes(<[u8]>::to_vec),
            b"new-native-secret"
        );
        assert_eq!(backend.occupied_slots(), 1);
        let payload_reads = backend.payload_reads;
        assert!(
            committed_provider_credential_source_slot(&mut backend, &access, [0xA5; 32],)
                .unwrap()
                .is_some()
        );
        assert_eq!(backend.payload_reads, payload_reads);
        assert!(backend.slots.iter().flatten().all(|item| {
            !item
                .metadata
                .windows(13)
                .any(|part| part == b"native-secret")
        }));
    }
}

fn unique_executable_copy(source: &std::path::Path) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "runne-secure-store-source-update-{}",
        std::process::id()
    ));
    std::fs::copy(source, &path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    path
}
