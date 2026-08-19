#[cfg(test)]
pub fn recover_provider_credential_source<B>(
    backend: &mut B,
    access: &ProviderCredentialAccessPolicy,
    acl_set_digest: [u8; 32],
) -> Result<Option<ProviderCredentialSource>, SecureStoreError>
where
    B: ProviderCredentialSourceSlotBackend,
{
    recover_provider_credential_record(backend, access, acl_set_digest)?
        .map(StoredProviderCredential::into_source)
        .transpose()
}

pub fn committed_provider_credential_source_slot<B>(
    backend: &mut B,
    access: &ProviderCredentialAccessPolicy,
    acl_set_digest: [u8; 32],
) -> Result<Option<ProviderCredentialSourceSlot>, SecureStoreError>
where
    B: ProviderCredentialSourceSlotBackend,
{
    let mut selected: Option<(ProviderCredentialSourceSlot, u64)> = None;
    let mut legacy_incomplete = false;
    let mut present = [false; 2];
    for slot in [
        ProviderCredentialSourceSlot::Primary,
        ProviderCredentialSourceSlot::Alternate,
    ] {
        let Some(encoded) = backend.load_metadata(slot)? else {
            continue;
        };
        present[slot.index()] = true;
        let metadata = ProviderCredentialMetadata::decode(&encoded)?;
        if !metadata.access_matches(access) {
            return Err(SecureStoreError::CredentialAclMigrationRequired);
        }
        if metadata.acl_set_digest() != acl_set_digest {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        let generation = match metadata.source_slot() {
            None if slot == ProviderCredentialSourceSlot::Primary && metadata.is_complete() => 0,
            None if slot == ProviderCredentialSourceSlot::Primary => {
                legacy_incomplete = true;
                continue;
            }
            Some(version)
                if version.slot == slot
                    && version.state == ProviderCredentialSourceSlotState::Committed
                    && metadata.is_complete() =>
            {
                version.generation
            }
            Some(version) if version.slot == slot => continue,
            _ => return Err(SecureStoreError::CorruptProviderCredential),
        };
        match selected {
            Some((_, current)) if current == generation => {
                return Err(SecureStoreError::CorruptProviderCredential);
            }
            Some((_, current)) if current > generation => {}
            _ => selected = Some((slot, generation)),
        }
    }
    if selected.is_none() && legacy_incomplete {
        return Err(SecureStoreError::CredentialEnrollmentIncomplete);
    }
    let selected = selected.map(|(slot, _)| slot);
    for slot in [
        ProviderCredentialSourceSlot::Primary,
        ProviderCredentialSourceSlot::Alternate,
    ] {
        if present[slot.index()] && Some(slot) != selected {
            backend.delete_slot(slot)?;
        }
    }
    Ok(selected)
}

pub fn recover_provider_credential_record<B>(
    backend: &mut B,
    access: &ProviderCredentialAccessPolicy,
    acl_set_digest: [u8; 32],
) -> Result<Option<StoredProviderCredential>, SecureStoreError>
where
    B: ProviderCredentialSourceSlotBackend,
{
    let mut slots = load_slots(backend, access, acl_set_digest)?;
    let selected = select_committed(&slots)?;
    cleanup_except(backend, &mut slots, selected)?;
    selected
        .map(|index| {
            slots[index]
                .take()
                .and_then(|slot| slot.stored)
                .ok_or(SecureStoreError::CorruptProviderCredential)
        })
        .transpose()
}

fn load_slots<B>(
    backend: &mut B,
    access: &ProviderCredentialAccessPolicy,
    acl_set_digest: [u8; 32],
) -> Result<[Option<LoadedSlot>; 2], SecureStoreError>
where
    B: ProviderCredentialSourceSlotBackend,
{
    Ok([
        load_slot(
            backend,
            ProviderCredentialSourceSlot::Primary,
            access,
            acl_set_digest,
        )?,
        load_slot(
            backend,
            ProviderCredentialSourceSlot::Alternate,
            access,
            acl_set_digest,
        )?,
    ])
}

fn load_slot<B>(
    backend: &mut B,
    slot: ProviderCredentialSourceSlot,
    access: &ProviderCredentialAccessPolicy,
    acl_set_digest: [u8; 32],
) -> Result<Option<LoadedSlot>, SecureStoreError>
where
    B: ProviderCredentialSourceSlotBackend,
{
    let Some(encoded_metadata) = backend.load_metadata(slot)? else {
        return Ok(None);
    };
    let metadata = ProviderCredentialMetadata::decode(&encoded_metadata)?;
    if !metadata.access_matches(access) {
        return Err(SecureStoreError::CredentialAclMigrationRequired);
    }
    if metadata.acl_set_digest() != acl_set_digest {
        return Err(SecureStoreError::CredentialAccessDenied);
    }
    if metadata
        .source_slot()
        .is_some_and(|version| version.slot != slot)
        || (slot == ProviderCredentialSourceSlot::Alternate && metadata.source_slot().is_none())
    {
        return Err(SecureStoreError::CorruptProviderCredential);
    }
    let stored = if metadata.is_complete() {
        let encoded = backend
            .load_encrypted_payload(slot)?
            .ok_or(SecureStoreError::CorruptProviderCredential)?;
        let stored = StoredProviderCredential::decode(&encoded)?;
        if !stored.metadata_matches(&metadata)
            || !stored.access_matches(access)
            || stored.acl_set_digest() != acl_set_digest
        {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        Some(stored)
    } else {
        None
    };
    Ok(Some(LoadedSlot {
        slot,
        metadata,
        stored,
    }))
}

fn select_committed(slots: &[Option<LoadedSlot>; 2]) -> Result<Option<usize>, SecureStoreError> {
    let mut selected: Option<(usize, u64)> = None;
    for (index, slot) in slots.iter().enumerate() {
        let Some(generation) = slot.as_ref().and_then(LoadedSlot::committed_generation) else {
            continue;
        };
        match selected {
            Some((_, current)) if current == generation => {
                return Err(SecureStoreError::CorruptProviderCredential);
            }
            Some((_, current)) if current > generation => {}
            _ => selected = Some((index, generation)),
        }
    }
    Ok(selected.map(|(index, _)| index))
}

fn next_target(
    slots: &[Option<LoadedSlot>; 2],
    selected: Option<usize>,
) -> Result<(ProviderCredentialSourceSlot, u64), SecureStoreError> {
    let Some(index) = selected else {
        return Ok((ProviderCredentialSourceSlot::Primary, 1));
    };
    let selected = slots[index].as_ref().expect("selected slot exists");
    let generation = selected
        .committed_generation()
        .and_then(|generation| generation.checked_add(1))
        .ok_or(SecureStoreError::CorruptProviderCredential)?;
    Ok((selected.slot.alternate(), generation))
}

fn reusable_pending(
    slot: Option<&LoadedSlot>,
    generation: u64,
    material: &ProviderCredentialMaterial,
    fallback: ProviderCredentialSourceRevision,
) -> (ProviderCredentialSourceRevision, bool) {
    let Some(slot) = slot else {
        return (fallback, false);
    };
    let Some(version) = slot.metadata.source_slot() else {
        return (fallback, false);
    };
    if version.state != ProviderCredentialSourceSlotState::Pending
        || version.generation != generation
    {
        return (fallback, false);
    }
    let revision = slot.metadata.source_revision().unwrap_or(fallback);
    let complete = slot
        .stored
        .as_ref()
        .is_some_and(|stored| stored.material_matches(material));
    (revision, complete)
}

fn cleanup_unrelated<B>(
    backend: &mut B,
    slots: &mut [Option<LoadedSlot>; 2],
    selected: Option<usize>,
    target: usize,
) -> Result<(), SecureStoreError>
where
    B: ProviderCredentialSourceSlotBackend,
{
    for (index, slot) in slots.iter_mut().enumerate() {
        if Some(index) != selected && index != target && slot.is_some() {
            backend.delete_slot(slot.as_ref().expect("slot exists").slot)?;
            *slot = None;
        }
    }
    Ok(())
}

fn cleanup_except<B>(
    backend: &mut B,
    slots: &mut [Option<LoadedSlot>; 2],
    selected: Option<usize>,
) -> Result<(), SecureStoreError>
where
    B: ProviderCredentialSourceSlotBackend,
{
    for (index, slot) in slots.iter_mut().enumerate() {
        if Some(index) != selected && slot.is_some() {
            backend.delete_slot(slot.as_ref().expect("slot exists").slot)?;
            *slot = None;
        }
    }
    Ok(())
}
