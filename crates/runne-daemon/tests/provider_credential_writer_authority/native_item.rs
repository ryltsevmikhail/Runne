use std::ffi::c_void;
use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant};

use core_foundation::base::{CFRelease, TCFType as _};
use core_foundation::data::CFData;
use security_framework::item::{
    ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue, SearchResult, update_item,
};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;

const ACCOUNT: &str = "openai";
const SERVICE_PREFIX: &str = "dev.runne.provider-credential.v1.version.";
const GENERIC_PASSWORD_ITEM_CLASS: u32 = u32::from_be_bytes(*b"genp");
const ACCOUNT_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"acct");
const SERVICE_ITEM_ATTRIBUTE: u32 = u32::from_be_bytes(*b"svce");

#[repr(C)]
struct KeychainAttribute {
    tag: u32,
    length: u32,
    data: *mut c_void,
}

#[repr(C)]
struct KeychainAttributeList {
    count: u32,
    attributes: *mut KeychainAttribute,
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainSearchCreateFromAttributes(
        keychain_or_array: *const c_void,
        item_class: u32,
        attributes: *const KeychainAttributeList,
        search: *mut *mut c_void,
    ) -> i32;
    fn SecKeychainSearchCopyNext(search: *mut c_void, item: *mut *mut c_void) -> i32;
}

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

pub(super) fn assert_unrelated_denied(
    root: &Path,
    runtime: &Path,
) -> Result<&'static str, &'static str> {
    let _interaction =
        SecKeychain::disable_user_interaction().map_err(|_| "disable-keychain-ui")?;
    let keychain = open_owned(root)?;
    let service = authority_service(runtime)?;
    let mut query = base_search(&keychain);
    query.service(&service);
    let item = await_exact_item(&keychain, &service)?;
    let expected = runne_macos_keychain_acl::ExactKeychainAccess::new(
        &root.join("Runne.app/Contents/MacOS/runne"),
        &root.join("Runne.app/Contents/MacOS/runned"),
    )
    .map_err(|_| "unrelated-expected-access")?;
    runne_macos_keychain_acl::verify_item_access(&item, expected.digest())
        .map_err(|_| "unrelated-original-access")?;
    let attacker_access = super::native_access::complex_attacker_access(&item)?;
    await_finalized_read_denial(&keychain, &service)?;

    let mut update = ItemUpdateOptions::new();
    update.set_value(ItemUpdateValue::Data(CFData::from_buffer(b"denied-update")));
    require_denial(update_item(&query, &update), "unrelated-update")?;
    require_denial(query.delete(), "unrelated-delete")?;
    let set_access_evidence =
        super::native_access::assert_replacement_denied(&item, &attacker_access)?;
    runne_macos_keychain_acl::verify_item_access(&item, expected.digest())
        .map_err(|_| "unrelated-access-changed")?;
    Ok(set_access_evidence)
}

fn authority_service(runtime: &Path) -> Result<String, &'static str> {
    let database = runtime.join("runne-daemon/event-log.db");
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| "native-item-sqlite")?;
    let (version, digest): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT COALESCE(allocated_credential_version, target_credential_version), \
             COALESCE(allocated_ref_digest, target_ref_digest) \
             FROM provider_credential_operations WHERE action IN ('PAIR', 'MIGRATE_LEGACY')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "native-item-authority")?;
    if version <= 0 || digest.len() != 32 {
        return Err("native-item-authority");
    }
    Ok(format!("{SERVICE_PREFIX}{version}.{}", hex::encode(digest)))
}

fn exact_item(keychain: &SecKeychain, service: &str) -> Result<SecKeychainItem, &'static str> {
    let mut attributes = [
        KeychainAttribute {
            tag: SERVICE_ITEM_ATTRIBUTE,
            length: service.len() as u32,
            data: service.as_ptr().cast_mut().cast(),
        },
        KeychainAttribute {
            tag: ACCOUNT_ITEM_ATTRIBUTE,
            length: ACCOUNT.len() as u32,
            data: ACCOUNT.as_ptr().cast_mut().cast(),
        },
    ];
    let attribute_list = KeychainAttributeList {
        count: attributes.len() as u32,
        attributes: attributes.as_mut_ptr(),
    };
    let mut search = ptr::null_mut();
    let create_status = unsafe {
        SecKeychainSearchCreateFromAttributes(
            keychain.as_CFTypeRef().cast(),
            GENERIC_PASSWORD_ITEM_CLASS,
            &raw const attribute_list,
            &raw mut search,
        )
    };
    if create_status != 0 || search.is_null() {
        return Err("native-item-search-create");
    }
    let mut item = ptr::null_mut();
    let status = unsafe { SecKeychainSearchCopyNext(search, &raw mut item) };
    unsafe { CFRelease(search.cast()) };
    if status != 0 || item.is_null() {
        return Err(match status {
            -25_293 => "native-item-search-next-auth-failed-25293",
            -25_300 => "native-item-search-next-not-found-25300",
            -25_308 => "native-item-search-next-interaction-not-allowed-25308",
            _ => "native-item-search-next",
        });
    }
    Ok(unsafe { SecKeychainItem::wrap_under_create_rule(item.cast()) })
}

fn await_exact_item(
    keychain: &SecKeychain,
    service: &str,
) -> Result<SecKeychainItem, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match exact_item(keychain, service) {
            Err("native-item-search-next-not-found-25300") if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            result => return result,
        }
    }
}

fn await_finalized_read_denial(keychain: &SecKeychain, service: &str) -> Result<(), &'static str> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut read = base_search(keychain);
        read.service(service).load_data(true);
        match read.search() {
            Err(error) if is_denial_code(error.code()) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return Err("unrelated-read"),
            Ok(results)
                if !results.is_empty()
                    && results.iter().all(
                        |result| matches!(result, SearchResult::Data(data) if data.is_empty()),
                    )
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(results)
                if results.iter().any(
                    |result| matches!(result, SearchResult::Data(data) if !data.is_empty()),
                ) =>
            {
                return Err("unrelated-pre-finalize-secret");
            }
            Ok(_) => return Err("unrelated-read-remained-visible"),
        }
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

fn require_denial<T>(
    result: security_framework::base::Result<T>,
    stage: &'static str,
) -> Result<(), &'static str> {
    match result {
        Err(error) if is_denial_code(error.code()) => Ok(()),
        Err(_) => Err(stage),
        Ok(_) => Err(stage),
    }
}

const fn is_denial_code(code: i32) -> bool {
    matches!(code, -25_293 | -25_300 | -25_308 | -25_243 | -25_244)
}
