// SPDX-License-Identifier: Apache-2.0
//! Real shared runtime using Rust fake capabilities, without platform C hooks.
use canokey_ports::Platform;
use canokey_rust_ffi::composition::{Provider, core};
use canokey_test_card::{Backend, Card};
use std::cell::RefCell;

thread_local! {
    static CARD: RefCell<Card> = RefCell::new(unsafe { Card::new() });
}
struct Fake;
impl Provider for Fake {
    type Backends = Backend;
    #[cfg(feature = "ctap")]
    type Staging = NoStaging;
    fn with_platform<T>(run: impl FnOnce(&mut Platform<'_, Backend>) -> T) -> T {
        CARD.with(|card| card.borrow_mut().run(|_, p| run(p)))
    }
}
#[cfg(feature = "ctap")]
struct NoStaging;
#[cfg(feature = "ctap")]
impl canokey_rust_ffi::composition::Staging for NoStaging {
    fn capacity() -> usize {
        0
    }
    fn acquire(_: u8) -> bool {
        false
    }
    fn clear() -> bool {
        false
    }
    fn release(_: u8) -> bool {
        false
    }
    fn read(_: usize, _: &mut [u8]) -> bool {
        false
    }
    fn write(_: usize, _: &[u8]) -> bool {
        false
    }
}
const OWNER_CCID: u8 = 1;
const RESPONSE_BYTES: usize = 258;
// SELECT ADMIN by its five-byte AID; profiles without ADMIN return 6A82.
const SELECT_ADMIN: &[u8] = &[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0];
#[cfg(feature = "admin")]
const QUERY_PIN: &[u8] = &[0, 0x20, 0, 0];
#[cfg(feature = "admin")]
const VERIFY_PIN: &[u8] = &[0, 0x20, 0, 0, 6, b'1', b'2', b'3', b'4', b'5', b'6'];
fn exchange(bytes: &[u8], expected: u16) {
    let mut buffer = [0; RESPONSE_BYTES];
    buffer[..bytes.len()].copy_from_slice(bytes);
    let count = unsafe {
        core::exchange::<Fake>(
            OWNER_CCID,
            buffer.as_ptr(),
            bytes.len(),
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    assert!(count >= 2);
    assert_eq!(
        &buffer[count as usize - 2..count as usize],
        expected.to_be_bytes()
    );
}
fn main() {
    assert_eq!(unsafe { core::install::<Fake>() }, 0);
    exchange(
        SELECT_ADMIN,
        if cfg!(feature = "admin") {
            0x9000
        } else {
            0x6a82
        },
    );
    #[cfg(feature = "admin")]
    {
        exchange(QUERY_PIN, 0x63c3);
        exchange(VERIFY_PIN, 0x9000);
        exchange(QUERY_PIN, 0x9000);
        unsafe { core::reset::<Fake>() };
        exchange(SELECT_ADMIN, 0x9000);
        exchange(QUERY_PIN, 0x63c3);
        exchange(VERIFY_PIN, 0x9000);
        unsafe { core::slot_power::<Fake>() };
        exchange(SELECT_ADMIN, 0x9000);
        exchange(QUERY_PIN, 0x63c3);
    }
    let mut out = [0; RESPONSE_BYTES];
    assert_eq!(
        unsafe {
            core::exchange::<Fake>(OWNER_CCID, std::ptr::null(), 0, out.as_mut_ptr(), out.len())
        },
        -1
    );
    assert_eq!(
        unsafe {
            core::exchange::<Fake>(
                OWNER_CCID,
                SELECT_ADMIN.as_ptr(),
                SELECT_ADMIN.len(),
                out.as_mut_ptr(),
                1,
            )
        },
        -1
    );
    println!("Outer runtime composition and alias-safe exchange passed");
}
