#![allow(unsafe_code)]

#[cfg(test)]
use std::cell::Cell;
use std::ffi::{c_char, c_void};
use std::ptr;

use zeroize::Zeroize;

use crate::ffi::PamResponse;

#[cfg(test)]
std::thread_local! {
    static LIVE_ALLOCATIONS: Cell<isize> = const { Cell::new(0) };
}

/// Owns malloc-compatible PAM responses until the full callback succeeds.
pub struct ResponseBuffer {
    pointer: *mut PamResponse,
    count: usize,
    secret_lengths: Vec<Option<usize>>,
    transferred: bool,
}

impl ResponseBuffer {
    pub(super) fn new(count: usize) -> Option<Self> {
        let secret_lengths = vec![None; count];
        // SAFETY: calloc returns aligned storage for the checked response count.
        let pointer = unsafe {
            tracked_calloc(count, std::mem::size_of::<PamResponse>()).cast::<PamResponse>()
        };
        (!pointer.is_null()).then_some(Self {
            pointer,
            count,
            secret_lengths,
            transferred: false,
        })
    }

    pub(super) fn set_secret(&mut self, index: usize, secret: &[u8]) -> Result<(), ()> {
        let allocation_length = secret.len().checked_add(1).ok_or(())?;
        // SAFETY: malloc returns writable storage for this bounded NUL-terminated response.
        let response = unsafe { tracked_malloc(allocation_length).cast::<u8>() };
        if response.is_null() {
            return Err(());
        }
        // SAFETY: `response` has the checked length and source does not overlap.
        unsafe {
            ptr::copy_nonoverlapping(secret.as_ptr(), response, secret.len());
            *response.add(secret.len()) = 0;
            (*self.pointer.add(index)).resp = response.cast::<c_char>();
            (*self.pointer.add(index)).resp_retcode = 0;
        }
        self.secret_lengths[index] = Some(allocation_length);
        Ok(())
    }

    pub(super) fn transfer(mut self) -> *mut PamResponse {
        self.transferred = true;
        self.pointer
    }
}

impl Drop for ResponseBuffer {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        for index in 0..self.count {
            // SAFETY: the response array belongs to this buffer until transfer.
            let response = unsafe { (*self.pointer.add(index)).resp };
            if !response.is_null() {
                if let Some(length) = self.secret_lengths[index] {
                    // SAFETY: the exact allocation length is recorded on copy.
                    unsafe { std::slice::from_raw_parts_mut(response.cast::<u8>(), length) }
                        .zeroize();
                }
                // SAFETY: response was allocated by libc::malloc in this module.
                unsafe { tracked_free(response.cast()) };
            }
        }
        // SAFETY: the response array was allocated by libc::calloc in this module.
        unsafe { tracked_free(self.pointer.cast()) };
    }
}

unsafe fn tracked_calloc(count: usize, size: usize) -> *mut c_void {
    // SAFETY: sizes are bounded by the caller's checked message count.
    let pointer = unsafe { libc::calloc(count, size) };
    if !pointer.is_null() {
        track_allocation(1);
    }
    pointer
}

unsafe fn tracked_malloc(size: usize) -> *mut c_void {
    // SAFETY: response size is checked before reaching this allocator.
    let pointer = unsafe { libc::malloc(size) };
    if !pointer.is_null() {
        track_allocation(1);
    }
    pointer
}

unsafe fn tracked_free(pointer: *mut c_void) {
    if !pointer.is_null() {
        // SAFETY: the pointer came from tracked_malloc or tracked_calloc.
        unsafe { libc::free(pointer) };
        track_allocation(-1);
    }
}

#[cfg(test)]
fn track_allocation(change: isize) {
    LIVE_ALLOCATIONS.with(|allocations| allocations.set(allocations.get() + change));
}

#[cfg(not(test))]
const fn track_allocation(_change: isize) {}

#[cfg(test)]
pub fn test_live_allocations() -> isize {
    LIVE_ALLOCATIONS.with(Cell::get)
}

#[cfg(test)]
pub struct TestResponse {
    pointer: *mut PamResponse,
    count: usize,
}

#[cfg(test)]
impl TestResponse {
    /// Wraps a response returned by the local PAM callback for ownership tests.
    ///
    /// # Safety
    ///
    /// `pointer` must be a non-null response array just transferred by `pam_conversation`.
    pub unsafe fn from_callback(pointer: *mut PamResponse, count: usize) -> Self {
        Self { pointer, count }
    }

    pub fn first_response_equals(&self, expected: &[u8]) -> bool {
        if self.pointer.is_null() || self.count == 0 {
            return false;
        }
        // SAFETY: this wrapper only accepts a live PAM callback response array.
        let response = unsafe { (*self.pointer).resp };
        if response.is_null() {
            return false;
        }
        let length = (0..=4096).find(|offset| {
            // SAFETY: callback responses are NUL-terminated within the known bound.
            unsafe { *response.add(*offset) == 0 }
        });
        let Some(length) = length else {
            return false;
        };
        // SAFETY: the scan found the terminator within the bounded callback response.
        unsafe { std::slice::from_raw_parts(response.cast::<u8>(), length) == expected }
    }
}

#[cfg(test)]
impl Drop for TestResponse {
    fn drop(&mut self) {
        for index in 0..self.count {
            // SAFETY: this wrapper uniquely owns the transferred response array.
            let response = unsafe { (*self.pointer.add(index)).resp };
            if !response.is_null() {
                let length = (0..=4096).find(|offset| {
                    // SAFETY: callback responses are NUL-terminated within the known bound.
                    unsafe { *response.add(*offset) == 0 }
                });
                if let Some(length) = length {
                    // SAFETY: the terminator bounds the full allocated C string.
                    unsafe { std::slice::from_raw_parts_mut(response.cast::<u8>(), length + 1) }
                        .zeroize();
                }
                // SAFETY: PAM-compatible responses were allocated by libc::malloc here.
                unsafe { tracked_free(response.cast()) };
            }
        }
        // SAFETY: this wrapper uniquely owns the transferred calloc response array.
        unsafe { tracked_free(self.pointer.cast()) };
    }
}
