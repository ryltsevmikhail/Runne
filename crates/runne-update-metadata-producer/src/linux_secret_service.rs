use dbus_secret_service::{EncryptionType, Item, Path, SecretService};

use crate::issuer::ProducerError;
use crate::key_store::KeySlot;

pub(crate) const SERVICE: &str = "runne.desktop.update-metadata/2";

pub(crate) fn read(slot: KeySlot) -> Result<Option<Vec<u8>>, ProducerError> {
    let service =
        SecretService::connect(EncryptionType::Dh).map_err(|_| ProducerError::KeyStore)?;
    let collection = service
        .get_default_collection()
        .map_err(|_| ProducerError::KeyStore)?;
    collection
        .ensure_unlocked()
        .map_err(|_| ProducerError::KeyStore)?;
    let matches = collection
        .search_items(slot_attributes(slot))
        .map_err(|_| ProducerError::KeyStore)?;
    match matches.as_slice() {
        [] => Ok(None),
        [item] => Ok(Some(
            item.get_secret().map_err(|_| ProducerError::KeyStore)?,
        )),
        _ => Err(ProducerError::KeyStore),
    }
}

pub(crate) fn create(slot: KeySlot, seed: &[u8]) -> Result<String, ProducerError> {
    let service =
        SecretService::connect(EncryptionType::Dh).map_err(|_| ProducerError::KeyStore)?;
    let collection = service
        .get_default_collection()
        .map_err(|_| ProducerError::KeyStore)?;
    collection
        .ensure_unlocked()
        .map_err(|_| ProducerError::KeyStore)?;
    let attributes = slot_attributes(slot);
    if !collection
        .search_items(attributes.clone())
        .map_err(|_| ProducerError::KeyStore)?
        .is_empty()
    {
        return Err(ProducerError::KeyStore);
    }
    let item = collection
        .create_item(
            &format!("Runne update metadata {}", slot.account()),
            attributes.clone(),
            seed,
            false,
            "application/octet-stream",
        )
        .map_err(|_| ProducerError::KeyStore)?;
    let identity = item.path.to_string();
    let matches = match collection.search_items(attributes) {
        Ok(matches) => matches,
        Err(_) => {
            delete_if_owned(&item, slot, seed)?;
            return Err(ProducerError::KeyStore);
        }
    };
    if matches.len() != 1 || matches[0].path != item.path {
        delete_if_owned(&item, slot, seed)?;
        return Err(ProducerError::KeyStore);
    }
    Ok(identity)
}

pub(crate) fn remove_if_value(
    slot: KeySlot,
    identity: &str,
    expected: &[u8],
) -> Result<(), ProducerError> {
    let service =
        SecretService::connect(EncryptionType::Dh).map_err(|_| ProducerError::KeyStore)?;
    let path = Path::new(identity.to_owned()).map_err(|_| ProducerError::KeyStore)?;
    let item = Item::new(&service, path);
    delete_if_owned(&item, slot, expected)
}

fn delete_if_owned(item: &Item<'_>, slot: KeySlot, expected: &[u8]) -> Result<(), ProducerError> {
    if !item_matches(item, slot, expected)? {
        return Err(ProducerError::KeyStore);
    }
    item.delete().map_err(|_| ProducerError::KeyStore)
}

fn item_matches(item: &Item<'_>, slot: KeySlot, expected: &[u8]) -> Result<bool, ProducerError> {
    let attributes = item.get_attributes().map_err(|_| ProducerError::KeyStore)?;
    if slot_attributes(slot)
        .iter()
        .any(|(key, value)| attributes.get(*key).map(String::as_str) != Some(*value))
    {
        return Ok(false);
    }
    Ok(item.get_secret().map_err(|_| ProducerError::KeyStore)? == expected)
}

pub(crate) fn slot_attributes(
    slot: KeySlot,
) -> std::collections::HashMap<&'static str, &'static str> {
    std::collections::HashMap::from([
        ("service", SERVICE),
        ("username", slot.account()),
        ("target", "default"),
        ("application", "rust-keyring"),
    ])
}
