use zeroize::Zeroizing;

#[cfg(test)]
use super::ProviderCredentialSource;
use super::{
    ProviderCredentialAccessPolicy, ProviderCredentialMaterial, ProviderCredentialMetadata,
    ProviderCredentialSourceRevision, SecureStoreError, StoredProviderCredential,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialSourceSlot {
    Primary,
    Alternate,
}

impl ProviderCredentialSourceSlot {
    pub const fn index(self) -> usize {
        match self {
            Self::Primary => 0,
            Self::Alternate => 1,
        }
    }

    pub const fn tag(self) -> u8 {
        match self {
            Self::Primary => 1,
            Self::Alternate => 2,
        }
    }

    const fn alternate(self) -> Self {
        match self {
            Self::Primary => Self::Alternate,
            Self::Alternate => Self::Primary,
        }
    }

    pub const fn from_tag(tag: u8) -> Result<Self, SecureStoreError> {
        match tag {
            1 => Ok(Self::Primary),
            2 => Ok(Self::Alternate),
            _ => Err(SecureStoreError::CorruptProviderCredential),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialSourceSlotState {
    Pending,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCredentialSourceSlotVersion {
    pub slot: ProviderCredentialSourceSlot,
    pub generation: u64,
    pub state: ProviderCredentialSourceSlotState,
}

impl ProviderCredentialSourceSlotVersion {
    pub const fn new(
        slot: ProviderCredentialSourceSlot,
        generation: u64,
        state: ProviderCredentialSourceSlotState,
    ) -> Result<Self, SecureStoreError> {
        if generation == 0 {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        Ok(Self {
            slot,
            generation,
            state,
        })
    }
}

pub trait ProviderCredentialSourceSlotBackend {
    fn load_metadata(
        &mut self,
        slot: ProviderCredentialSourceSlot,
    ) -> Result<Option<Vec<u8>>, SecureStoreError>;
    fn load_encrypted_payload(
        &mut self,
        slot: ProviderCredentialSourceSlot,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError>;
    fn create_incomplete(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        metadata: &[u8],
    ) -> Result<(), SecureStoreError>;
    fn write_encrypted_payload(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        payload: &[u8],
    ) -> Result<(), SecureStoreError>;
    fn atomic_write_metadata(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        metadata: &[u8],
    ) -> Result<(), SecureStoreError>;
    fn delete_slot(&mut self, slot: ProviderCredentialSourceSlot) -> Result<(), SecureStoreError>;
}

struct LoadedSlot {
    slot: ProviderCredentialSourceSlot,
    metadata: ProviderCredentialMetadata,
    stored: Option<StoredProviderCredential>,
}

impl LoadedSlot {
    fn committed_generation(&self) -> Option<u64> {
        if !self.metadata.is_complete() {
            return None;
        }
        match self.metadata.source_slot() {
            None if self.slot == ProviderCredentialSourceSlot::Primary => Some(0),
            Some(version) if version.state == ProviderCredentialSourceSlotState::Committed => {
                Some(version.generation)
            }
            _ => None,
        }
    }
}

pub fn commit_provider_credential_source_update<B>(
    backend: &mut B,
    material: &ProviderCredentialMaterial,
    access: &ProviderCredentialAccessPolicy,
    acl_set_digest: [u8; 32],
    proposed_revision: ProviderCredentialSourceRevision,
) -> Result<ProviderCredentialSourceRevision, SecureStoreError>
where
    B: ProviderCredentialSourceSlotBackend,
{
    let mut slots = load_slots(backend, access, acl_set_digest)?;
    let selected = select_committed(&slots)?;
    if let Some(index) = selected {
        let selected_slot = slots[index].as_ref().expect("selected slot exists");
        if selected_slot.metadata.source_slot().is_some()
            && selected_slot
                .stored
                .as_ref()
                .is_some_and(|stored| stored.material_matches(material))
        {
            let revision = selected_slot
                .metadata
                .source_revision()
                .ok_or(SecureStoreError::CorruptProviderCredential)?;
            cleanup_except(backend, &mut slots, Some(index))?;
            return Ok(revision);
        }
    }
    let (target, generation) = next_target(&slots, selected)?;
    let target_index = target.index();
    cleanup_unrelated(backend, &mut slots, selected, target_index)?;
    let (revision, pending_complete) = reusable_pending(
        slots[target_index].as_ref(),
        generation,
        material,
        proposed_revision,
    );
    if slots[target_index].is_some() && revision == proposed_revision && !pending_complete {
        backend.delete_slot(target)?;
        slots[target_index] = None;
    }
    let pending_version = ProviderCredentialSourceSlotVersion::new(
        target,
        generation,
        ProviderCredentialSourceSlotState::Pending,
    )?;
    let pending = ProviderCredentialMetadata::from_source_slot(
        access,
        acl_set_digest,
        revision,
        pending_version,
    );
    if slots[target_index].is_none() {
        backend.create_incomplete(target, &pending.encode_incomplete())?;
    }
    if !pending_complete {
        let encoded = StoredProviderCredential::encode_with_revision(
            material,
            access,
            acl_set_digest,
            revision,
        )?;
        backend.write_encrypted_payload(target, &encoded)?;
        backend.atomic_write_metadata(target, &pending.encode())?;
    }
    let committed = ProviderCredentialMetadata::from_source_slot(
        access,
        acl_set_digest,
        revision,
        ProviderCredentialSourceSlotVersion::new(
            target,
            generation,
            ProviderCredentialSourceSlotState::Committed,
        )?,
    );
    backend.atomic_write_metadata(target, &committed.encode())?;
    if let Some(index) = selected {
        backend.delete_slot(slots[index].as_ref().expect("selected slot exists").slot)?;
    }
    Ok(revision)
}

include!("source_update_recovery.rs");
