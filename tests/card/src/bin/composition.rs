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
    pointer_guards();
    #[cfg(feature = "openpgp")]
    aliased_response_regressions();
    unsafe { core::reset::<Fake>() };
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

fn pointer_guards() {
    // Short SELECT with an unknown AID is valid input for every profile.
    const REQUEST: &[u8] = &[0, 0xa4, 4, 0, 1, 0xff];
    let mut out = [0xa5; RESPONSE_BYTES];
    for (input, len, output, capacity) in [
        (std::ptr::null(), REQUEST.len(), out.as_mut_ptr(), out.len()),
        (
            REQUEST.as_ptr(),
            REQUEST.len(),
            std::ptr::null_mut(),
            out.len(),
        ),
        (REQUEST.as_ptr(), usize::MAX, out.as_mut_ptr(), out.len()),
        (
            REQUEST.as_ptr(),
            REQUEST.len(),
            out.as_mut_ptr(),
            usize::MAX,
        ),
        (REQUEST.as_ptr(), REQUEST.len(), out.as_mut_ptr(), 0),
        (REQUEST.as_ptr(), REQUEST.len(), out.as_mut_ptr(), 1),
    ] {
        assert_eq!(
            unsafe { core::exchange::<Fake>(OWNER_CCID, input, len, output, capacity) },
            -1
        );
    }
    assert_eq!(out, [0xa5; RESPONSE_BYTES]);
}

#[cfg(feature = "openpgp")]
fn aliased_response_regressions() {
    use canokey_ports::{Record, Storage};
    const CERTIFICATE_BYTES: usize = 600;
    const ARENA_BYTES: usize = 272;
    // OpenPGP SELECT, certificate GET DATA, and GET RESPONSE with Le=256.
    const SELECT: &[u8] = &[0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1];
    const READ: &[u8] = &[0, 0xca, 0x7f, 0x21, 0];
    const NEXT: &[u8] = &[0, 0xc0, 0, 0, 0];
    let payload: [u8; CERTIFICATE_BYTES] = std::array::from_fn(|i| (i * 7 + 1) as u8);
    CARD.with(|card| {
        card.borrow_mut()
            .records
            .replace(Record::PgpCertSig, &payload)
            .unwrap()
    });
    for (variant, first_capacity) in [250, 249, 3, 2].into_iter().enumerate() {
        unsafe { core::reset::<Fake>() };
        exchange(SELECT, 0x9000);
        let mut offset = 0;
        for round in 0..10 {
            if offset == payload.len() {
                break;
            }
            let mut arena = [0xa5; ARENA_BYTES];
            arena[1..1 + READ.len()].copy_from_slice(if round == 0 { READ } else { NEXT });
            let before = arena;
            let capacity = if round == 0 {
                first_capacity
            } else if variant == 2 {
                202
            } else {
                RESPONSE_BYTES
            };
            let n = unsafe {
                core::exchange::<Fake>(
                    OWNER_CCID,
                    arena.as_ptr().add(1),
                    READ.len(),
                    arena.as_mut_ptr().add(1),
                    capacity,
                )
            };
            let count =
                (payload.len() - offset).min(capacity - canokey_protocol::apdu::STATUS_BYTES);
            assert_eq!(n as usize, count + canokey_protocol::apdu::STATUS_BYTES);
            assert_eq!(&arena[1..1 + count], &payload[offset..offset + count]);
            offset += count;
            let remaining = payload.len() - offset;
            let status: u16 = if remaining == 0 {
                0x9000
            } else {
                0x6100 | remaining.min(255) as u16
            };
            assert_eq!(&arena[1 + count..3 + count], status.to_be_bytes());
            assert_eq!(arena[0], 0xa5);
            assert_eq!(&arena[1 + capacity..], &before[1 + capacity..]);
        }
        assert_eq!(offset, payload.len());
        exchange(NEXT, 0x6986);
    }
}
