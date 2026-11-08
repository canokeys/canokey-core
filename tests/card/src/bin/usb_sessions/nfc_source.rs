// SPDX-License-Identifier: Apache-2.0
//! Source faults through production NFC dispatch, with one Provider per process.
use super::*;
use canokey_ports::{
    BackendTypes, Crypto, CryptoError, KeyMaterial, KeyOperation, Memory, MemoryBackend, Platform,
};
use canokey_rust_ffi::composition::{Provider, Staging, nfc};
use std::cell::Cell;

// Standard NFC FIDO SELECT and clientPIN getKeyAgreement, protocol1.
const SELECT: &[u8] = b"\x00\xa4\x04\x00\x08\xa0\x00\x00\x06\x47\x2f\x00\x01";
const AGREEMENT: &[u8] = &[0x80, 0x10, 0, 0, 6, 6, 0xa2, 1, 1, 2, 2];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Read(usize),
    Before(usize),
    After(usize),
    Wipe(usize),
    Clear,
    Release,
}
thread_local! {
    static DESELECT: Cell<bool> = const { Cell::new(false) };
    static SOURCE_WIPES: Cell<usize> = const { Cell::new(0) };
    static WIPE_READS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    static FAULT: Cell<Fault> = const { Cell::new(Fault::None) };
    static FIRED: Cell<bool> = const { Cell::new(false) };
    static READS: Cell<usize> = const { Cell::new(0) };
    static WIPES: Cell<usize> = const { Cell::new(0) };
    static CLEARS: Cell<usize> = const { Cell::new(0) };
    static RELEASES: Cell<usize> = const { Cell::new(0) };
    static KEYS: Cell<usize> = const { Cell::new(0) };
    static WRITES: Cell<usize> = const { Cell::new(0) };
    static RETRY_WRITE: Cell<usize> = const { Cell::new(0) };
}
fn interrupt(at: Fault) {
    if FAULT.get() == at {
        FAULT.set(Fault::None);
        FIRED.set(true);
        // Only IRQ-local state may change while Core/Provider is borrowed.
        if DESELECT.get() {
            // A reader may send deselect once WTX has returned the RF turn.
            // Before that, the current I-block still owns its pending reply.
            super::portable_nfc::waiting_turn();
            super::portable_nfc::input(&packet(canokey_protocol::nfc::PCB_DESELECT, &[]));
        } else {
            super::portable_nfc::halt();
        }
    }
}
struct Fake;
struct Stage;
struct Erasure;
struct Primitives(canokey_native_crypto::CryptoBackend);
impl Crypto for Primitives {
    fn key_operation(
        &mut self,
        op: KeyOperation,
        alg: u8,
        key: &mut KeyMaterial,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert_eq!(
            transport::scratch(|s| s.owner),
            0,
            "crypto while NFC source is live"
        );
        KEYS.set(KEYS.get() + 1);
        self.0.key_operation(op, alg, key, input, out)
    }
    fn mac(
        &mut self,
        alg: u8,
        key: &[u8],
        input: &[u8],
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        self.0.mac(alg, key, input, out)
    }
    fn random(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.0.random(out)
    }
    fn hmac_sha1(&mut self, key: &[u8; 20], input: &[u8], out: &mut [u8; 20]) {
        self.0.hmac_sha1(key, input, out);
    }
}
impl Provider for Fake {
    type Backends =
        BackendTypes<canokey_test_card::storage::Records, Primitives, transport::Clock, Erasure>;
    type Staging = Stage;
    fn with_platform<T>(run: impl FnOnce(&mut Platform<'_, Self::Backends>) -> T) -> T {
        // Use an owned native adapter: no lifetime extension or Provider switch.
        transport::records(|storage| {
            let mut crypto = Primitives(unsafe { canokey_native_crypto::CryptoBackend::new() });
            run(&mut Platform::new(
                storage,
                &mut crypto,
                &mut transport::Clock,
                &Erasure,
            ))
        })
    }
}
impl Memory for Erasure {
    fn wipe(&self, bytes: &mut [u8]) {
        MemoryBackend.wipe(bytes);
        // Window erasures occur after parser consumption, including the final read.
        if READS.get() != 0 && bytes.len() == 64 {
            WIPES.set(WIPES.get() + 1);
            WIPE_READS.with(|r| r.borrow_mut().push(READS.get()));
            interrupt(Fault::Wipe(WIPES.get()));
        }
    }
}
impl Staging for Stage {
    fn capacity() -> usize {
        transport::Scratch::capacity()
    }
    fn acquire(owner: u8) -> bool {
        transport::Scratch::acquire(owner)
    }
    fn clear() -> bool {
        CLEARS.set(CLEARS.get() + 1);
        SOURCE_WIPES.set(WIPES.get());
        let ok = transport::Scratch::clear();
        interrupt(Fault::Clear);
        ok
    }
    fn release(owner: u8) -> bool {
        RELEASES.set(RELEASES.get() + 1);
        let ok = transport::Scratch::release(owner);
        interrupt(Fault::Release);
        ok
    }
    fn read(offset: usize, out: &mut [u8]) -> bool {
        READS.set(READS.get() + 1);
        let at = READS.get();
        interrupt(Fault::Before(at));
        if FAULT.get() == Fault::Read(at) {
            FAULT.set(Fault::None);
            FIRED.set(true);
            out.fill(0xa5); // A failed source may have modified the destination.
            return false;
        }
        let ok = transport::Scratch::read(offset, out);
        interrupt(Fault::After(at));
        ok
    }
    fn write(offset: usize, bytes: &[u8]) -> bool {
        let ok = transport::Scratch::write(offset, bytes);
        WRITES.set(WRITES.get() + 1);
        if RETRY_WRITE.get() == WRITES.get() {
            RETRY_WRITE.set(0);
            FIRED.set(true);
            // IRQ-local receive only: Core is still appending its claimed
            // original I-block to PKE and must retain that frame's reply turn.
            super::portable_nfc::input(&packet(canokey_protocol::nfc::PCB_NAK, &[]));
        }
        ok
    }
}
fn packet(pcb: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![pcb];
    frame.extend_from_slice(body);
    frame.extend_from_slice(&[0; 2]); // Chip-checked receive CRC.
    frame
}
fn send(frame: &[u8]) -> Vec<u8> {
    super::portable_nfc::input(frame);
    unsafe {
        nfc::poll::<Fake>();
        nfc::poll::<Fake>();
    }
    super::portable_nfc::response()
}
fn exchange(bytes: &[u8], number: &mut u8) -> Vec<u8> {
    use canokey_protocol::nfc as wire;
    let mut response = Vec::new();
    for (i, part) in bytes.chunks(20).enumerate() {
        let last = (i + 1) * 20 >= bytes.len();
        let pcb = wire::PCB_I | *number | if last { 0 } else { wire::PCB_CHAIN_OR_NAK };
        let reply = send(&packet(pcb, part));
        *number ^= wire::PCB_NUMBER;
        if last {
            response = reply;
        } else {
            assert_eq!(reply, [wire::PCB_ACK | (*number ^ 1)]);
        }
    }
    let mut result = Vec::new();
    while !response.is_empty() {
        result.extend_from_slice(&response[1..]);
        if response[0] & wire::PCB_CHAIN_OR_NAK == 0 {
            break;
        }
        response = send(&packet(wire::PCB_ACK | *number, &[]));
        *number ^= wire::PCB_NUMBER;
    }
    result
}
fn reset() -> u8 {
    FAULT.set(Fault::None);
    unsafe {
        nfc::init::<Fake>();
    }
    let mut number = 0;
    sw(&exchange(SELECT, &mut number), 0x9000);
    READS.set(0);
    WIPES.set(0);
    WIPE_READS.with(|r| r.borrow_mut().clear());
    CLEARS.set(0);
    RELEASES.set(0);
    KEYS.set(0);
    FIRED.set(false);
    WRITES.set(0);
    RETRY_WRITE.set(0);
    number
}
pub(super) fn run() {
    hw(|h| h.masked = 0);
    transport::device_hooks(now, || true);
    assert_eq!(unsafe { core::install::<Fake>() }, 0);
    // Exercise the minimal staged case and the actual CanoKey request ceiling.
    // No product limit is enlarged to impersonate the vLEI 2048-byte profile.
    for body_bytes in [291, canokey_rust_core::config::CTAP_MAX_REQUEST] {
        run_length(body_bytes);
    }
}
fn run_length(body_bytes: usize) {
    // CTAP clientPIN getKeyAgreement: command 06, map A3, protocol 01,
    // subcommand 02, then unknown key 99 and a definite 16-bit-length bstr.
    const PARAMETER_PREFIX_BYTES: usize = 11;
    let padding_bytes = body_bytes - PARAMETER_PREFIX_BYTES;
    let mut bytes = vec![0x80, 0x10, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&(body_bytes as u16).to_be_bytes());
    bytes.extend_from_slice(&[0x06, 0xa3, 0x01, 0x01, 0x02, 0x02, 0x18, 0x63, 0x59]);
    bytes.extend_from_slice(&(padding_bytes as u16).to_be_bytes());
    bytes.extend(std::iter::repeat_n(0x37, padding_bytes));
    let mut number = reset();
    let reply = exchange(&bytes, &mut number);
    sw(&reply, 0x9000);
    assert_eq!(reply[0], 0);
    assert_eq!(KEYS.get(), 2);
    let writes = WRITES.get();
    let reads = READS.get();
    assert!(reads > 1);
    let wipes = SOURCE_WIPES.get();
    assert!(wipes >= reads);
    let wipe_reads = WIPE_READS.with(|r| r.borrow()[..wipes].to_vec());
    for at in 1..=writes {
        let mut number = reset();
        RETRY_WRITE.set(at);
        let reply = exchange(&bytes, &mut number);
        assert!(FIRED.get(), "unreached write{at}");
        sw(&reply, 0x9000);
        assert_eq!(reply[0], 0);
        assert_eq!(KEYS.get(), 2);
        assert_eq!((CLEARS.get(), RELEASES.get()), (1, 1));
        assert_eq!(transport::scratch(|s| s.owner), 0);
        let recovered = exchange(AGREEMENT, &mut number);
        sw(&recovered, 0x9000);
        assert_eq!(recovered[0], 0);
    }
    println!(
        "NFC_INPUT_RETRY body={body_bytes} writes={writes} cases={writes} preserved=1 recovery=pass"
    );
    let mut faults = vec![Fault::Clear, Fault::Release];
    for n in 1..=reads {
        faults.extend([Fault::Read(n), Fault::Before(n), Fault::After(n)]);
    }
    // Limit to consumer-window wipes before source.close. Later applet erasures
    // are execution cancellation, outside this source-before-dispatch contract.
    for n in 1..=wipes {
        faults.push(Fault::Wipe(n));
    }
    let mut cases = 0;
    for deselect in [false, true] {
        DESELECT.set(deselect);
        for fault in &faults {
            if deselect && matches!(fault, Fault::Read(_)) {
                continue;
            }
            let mut number = reset();
            FAULT.set(*fault);
            let reply = exchange(&bytes, &mut number);
            assert!(FIRED.get(), "unreached {fault:?}");
            assert_eq!(KEYS.get(), 0, "cancelled source dispatched: {fault:?}");
            let expected_reads = match fault {
                Fault::Read(n) | Fault::Before(n) | Fault::After(n) => *n,
                Fault::Wipe(n) => wipe_reads[*n - 1],
                _ => reads,
            };
            assert_eq!(
                READS.get(),
                expected_reads,
                "read after cancellation: {fault:?}"
            );
            assert_eq!((CLEARS.get(), RELEASES.get()), (1, 1));
            assert_eq!(transport::scratch(|s| s.owner), 0);
            if matches!(fault, Fault::Read(_)) {
                assert_eq!(reply, [0x69, 0]);
                // A reader failure preserves activation and explicit selection.
                let recovered = exchange(AGREEMENT, &mut number);
                sw(&recovered, 0x9000);
                assert_eq!(recovered[0], 0);
            } else {
                assert!(
                    reply.is_empty(),
                    "cancelled activation transmitted {fault:?}"
                );
                if deselect {
                    // Deselect cancels without changing the activation generation;
                    // its echo follows Core cleanup and contains no APDU response.
                    unsafe {
                        nfc::poll::<Fake>();
                    }
                    assert_eq!(
                        super::portable_nfc::response(),
                        [canokey_protocol::nfc::PCB_DESELECT]
                    );
                }
                // Cancellation cleanup revokes selection before the next activation.
                unsafe {
                    nfc::init::<Fake>();
                }
                number = 0;
                sw(&exchange(AGREEMENT, &mut number), 0x6a82);
                sw(&exchange(SELECT, &mut number), 0x9000);
                let recovered = exchange(AGREEMENT, &mut number);
                sw(&recovered, 0x9000);
                assert_eq!(recovered[0], 0);
            }
            println!(
                "NFC_SOURCE_CASE body={body_bytes} deselect={deselect} fault={fault:?} reads={expected_reads} clear=1 release=1 keys_before_dispatch=0 recovery=pass"
            );
            cases += 1;
        }
    }
    println!(
        "NFC_SOURCE_FAULTS body={body_bytes} reads={reads} consumer_wipes={wipes} cases={cases} passed"
    );
}
