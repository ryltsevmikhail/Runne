use std::path::Path;

use core_foundation::data::CFData;
use security_framework::item::{
    ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue, SearchResult, update_item,
};
use security_framework::os::macos::keychain::SecKeychain;

const ACCOUNT: &str = "openai";
const SERVICE_PREFIX: &str = "dev.runne.provider-credential.v1.version.";

pub(super) fn assert_absent(root: &Path) -> Result<(), &'static str> {
    (!exists(root)?)
        .then_some(())
        .ok_or("native-effect-present")
}

pub(super) fn exists(root: &Path) -> Result<bool, &'static str> {
    let keychain = open_owned(root)?;
    let mut search = base_search(&keychain);
    search.load_attributes(true);
    match search.search() {
        Ok(results) => Ok(!results.is_empty()),
        Err(error) if error.code() == -25_300 => Ok(false),
        Err(_) => Err("native-item-search"),
    }
}

pub(super) fn assert_unrelated_denied(root: &Path) -> Result<(), &'static str> {
    let _interaction =
        SecKeychain::disable_user_interaction().map_err(|_| "disable-keychain-ui")?;
    let keychain = open_owned(root)?;
    let service = discover_service(&keychain)?;
    let mut query = base_search(&keychain);
    query.service(&service);

    let mut read = base_search(&keychain);
    read.service(&service).load_data(true);
    require_denial(read.search().map(|_| ()), "unrelated-read")?;

    let mut update = ItemUpdateOptions::new();
    update.set_value(ItemUpdateValue::Data(CFData::from_buffer(b"denied-update")));
    require_denial(update_item(&query, &update), "unrelated-update")?;
    require_denial(query.delete(), "unrelated-delete")?;
    if keychain
        .add_generic_password(&service, ACCOUNT, b"denied-create")
        .is_ok()
    {
        return Err("unrelated-create");
    }
    exists(root)?.then_some(()).ok_or("native-item-lost")
}

fn discover_service(keychain: &SecKeychain) -> Result<String, &'static str> {
    let mut search = base_search(keychain);
    search.load_attributes(true);
    search
        .search()
        .map_err(|_| "native-item-attributes")?
        .into_iter()
        .filter_map(|result| match result {
            SearchResult::Dict(_) => result.simplify_dict(),
            _ => None,
        })
        .flat_map(|attributes| attributes.into_values())
        .find(|value| value.starts_with(SERVICE_PREFIX))
        .ok_or("native-item-service")
}

fn base_search(keychain: &SecKeychain) -> ItemSearchOptions {
    let mut search = ItemSearchOptions::new();
    search
        .keychains(std::slice::from_ref(keychain))
        .class(ItemClass::generic_password())
        .account(ACCOUNT);
    search
}

fn open_owned(root: &Path) -> Result<SecKeychain, &'static str> {
    let path = std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN")
        .map(std::path::PathBuf::from)
        .ok_or("keychain-env")?;
    let expected = root.join("home/Library/Keychains/runne-ci.keychain-db");
    (path == expected && path.is_file())
        .then_some(())
        .ok_or("keychain-scope")?;
    SecKeychain::open(path).map_err(|_| "keychain-open")
}

fn require_denial<T>(
    result: security_framework::base::Result<T>,
    stage: &'static str,
) -> Result<(), &'static str> {
    match result {
        Err(error)
            if matches!(
                error.code(),
                -25_293 | -25_300 | -25_308 | -25_243 | -25_244
            ) =>
        {
            Ok(())
        }
        Err(_) => Err(stage),
        Ok(_) => Err(stage),
    }
}
