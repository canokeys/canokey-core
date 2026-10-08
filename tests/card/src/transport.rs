// SPDX-License-Identifier: Apache-2.0
//! Direct Rust capability fakes for tests of the shared transport composition.
use crate::storage::Records;
use canokey_ports::{BackendTypes, Device, MemoryBackend, Platform};
use canokey_rust_ffi::composition::{Provider, Staging};
use std::cell::{Cell, RefCell};
pub const SCRATCH_BYTES: usize = 48 * 64;
thread_local! {
    static RECORDS: RefCell<Records> = RefCell::new(Records::new());
    static NOW: Cell<fn() -> u32> = Cell::new(|| 0);
    static PROGRESS: Cell<fn() -> bool> = Cell::new(|| false);
    static SCRATCH: RefCell<Scratch> = const { RefCell::new(Scratch {
        bytes: [0; SCRATCH_BYTES], owner: 0, leases: 0, clears: 0,
    }) };
}
pub fn records<T>(run: impl FnOnce(&mut Records) -> T) -> T {
    RECORDS.with(|records| run(&mut records.borrow_mut()))
}
pub fn device_hooks(now: fn() -> u32, progress: fn() -> bool) {
    NOW.set(now);
    PROGRESS.set(progress);
}
pub struct Clock;
impl Device for Clock {
    fn serial(&mut self, out: &mut [u8; 4]) {
        out.fill(0);
    }
    fn now(&mut self) -> u32 {
        NOW.with(|f| f.get()())
    }
    fn touched(&mut self) -> bool {
        false
    }
    fn progress(&mut self) -> bool {
        PROGRESS.with(|f| f.get()())
    }
    fn keepalive(&mut self, waiting: bool) {
        unsafe { canokey_rust_ffi::composition::hid::keepalive(waiting) }
    }
    fn led(&mut self, _: bool) {}
}
pub struct Fake;
impl Provider for Fake {
    type Backends =
        BackendTypes<Records, canokey_native_crypto::CryptoBackend, Clock, MemoryBackend>;
    type Staging = Scratch;
    fn with_platform<T>(run: impl FnOnce(&mut Platform<'_, Self::Backends>) -> T) -> T {
        records(|storage| {
            let mut crypto = unsafe { canokey_native_crypto::CryptoBackend::new() };
            run(&mut Platform::new(
                storage,
                &mut crypto,
                &mut Clock,
                &MemoryBackend,
            ))
        })
    }
}
pub struct Scratch {
    bytes: [u8; SCRATCH_BYTES],
    pub owner: u8,
    pub leases: usize,
    pub clears: usize,
}
pub fn scratch<T>(run: impl FnOnce(&Scratch) -> T) -> T {
    SCRATCH.with(|scratch| run(&scratch.borrow()))
}
impl Staging for Scratch {
    fn capacity() -> usize {
        SCRATCH_BYTES
    }
    fn acquire(owner: u8) -> bool {
        SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            if owner == 0 || scratch.owner != 0 {
                return false;
            }
            scratch.owner = owner;
            scratch.leases += 1;
            true
        })
    }
    fn clear() -> bool {
        SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            assert_ne!(scratch.owner, 0);
            scratch.bytes.fill(0);
            scratch.clears += 1;
            true
        })
    }
    fn release(owner: u8) -> bool {
        SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            assert_eq!(scratch.owner, owner);
            assert_ne!(owner, 0);
            assert!(scratch.bytes.iter().all(|b| *b == 0));
            scratch.owner = 0;
            true
        })
    }
    fn read(offset: usize, out: &mut [u8]) -> bool {
        SCRATCH.with(|scratch| {
            let scratch = scratch.borrow();
            if scratch.owner == 0 {
                return false;
            }
            let Some(bytes) = offset
                .checked_add(out.len())
                .and_then(|end| scratch.bytes.get(offset..end))
            else {
                return false;
            };
            out.copy_from_slice(bytes);
            true
        })
    }
    fn write(offset: usize, input: &[u8]) -> bool {
        SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            if scratch.owner == 0 {
                return false;
            }
            let Some(bytes) = offset
                .checked_add(input.len())
                .and_then(|end| scratch.bytes.get_mut(offset..end))
            else {
                return false;
            };
            bytes.copy_from_slice(input);
            true
        })
    }
}
