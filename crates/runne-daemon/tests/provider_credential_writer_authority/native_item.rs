use std::path::Path;

use security_framework::item::{ItemClass, ItemSearchOptions};
use security_framework::os::macos::keychain::SecKeychain;

const ACCOUNT: &str = "openai";

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
