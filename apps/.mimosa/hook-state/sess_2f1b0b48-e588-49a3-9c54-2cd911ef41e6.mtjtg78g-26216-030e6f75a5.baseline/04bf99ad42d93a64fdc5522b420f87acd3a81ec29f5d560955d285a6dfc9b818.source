//! Audited unsafe bridge for `AppKit` objects owned by the exact Tauri window.

#![allow(unsafe_code)]

use std::ptr;

use objc2::MainThreadMarker;
use objc2::rc::Retained;
use objc2_app_kit::NSWindow;
use objc2_foundation::{
    NSRange, NSString, NSStringEncodingConversionOptions, NSUTF8StringEncoding,
};
use tauri::WebviewWindow;
use zeroize::Zeroizing;

/// Retains the exact Tauri `NSWindow` while holding main-thread authority.
pub(super) fn retain_tauri_window(
    _mtm: MainThreadMarker,
    window: &WebviewWindow,
) -> Option<Retained<NSWindow>> {
    let raw = window.ns_window().ok()?.cast::<NSWindow>();
    // SAFETY: Tauri returns a valid autoreleased NSWindow pointer on macOS.
    // MainThreadMarker proves the caller is on AppKit's main thread; retaining
    // the object makes its lifetime independent from the Tauri handle borrow.
    unsafe { Retained::retain(raw) }
}

/// Copies `NSString` UTF-8 bytes directly into zeroizing storage.
pub(super) fn copy_utf8(value: &NSString, maximum: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
    let length = value.lengthOfBytesUsingEncoding(NSUTF8StringEncoding);
    if length == 0 || length > maximum {
        return Err(());
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    let mut used = 0;
    // SAFETY: `bytes` owns `length` writable bytes; `used` is valid; the
    // source range is the complete NSString and no remaining range is needed.
    let copied = unsafe {
        value.getBytes_maxLength_usedLength_encoding_options_range_remainingRange(
            bytes.as_mut_ptr().cast(),
            length,
            &raw mut used,
            NSUTF8StringEncoding,
            NSStringEncodingConversionOptions::empty(),
            NSRange::new(0, value.length()),
            ptr::null_mut(),
        )
    };
    if !copied || used != length {
        return Err(());
    }
    Ok(bytes)
}
