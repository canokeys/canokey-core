// SPDX-License-Identifier: Apache-2.0
//! PC/SC slot/session policy. The native IFD shim translates platform types and
//! constants only. Every entry touching CORE takes ENTRY, across host threads.
use super::*;
const OK: i32 = 0;
const COMM: i32 = 1;
const SMALL: i32 = 2;
const UNSUPPORTED: i32 = 3;
const MISSING: i32 = 4;
const PROTOCOL: i32 = 5;
const TAG: i32 = 6;
const ATR: &[u8] = &[
    0x3b, 0xf7, 0x11, 0, 0, 0x81, 0x31, 0xfe, 0x65, 0x43, 0x61, 0x6e, 0x6f, 0x4b, 0x65, 0x79, 0x99,
];
fn valid(lun: u64) -> bool {
    HOST.lock()
        .unwrap()
        .as_ref()
        .is_some_and(|h| h.pcsc_lun == Some(lun))
}
fn contactless() -> bool {
    for name in ["CANOKEY_TEST_NFC", "CANOKEY_VIRT_NFC"] {
        if std::env::var(name).is_ok_and(|s| !s.is_empty()) {
            return flag(name, false);
        }
    }
    std::fs::read_to_string("/tmp/canokey-test-nfc")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|n| n != 0)
}
unsafe fn copy(bytes: &[u8], out: *mut u8, cap: usize, length: *mut usize) -> i32 {
    if length.is_null() {
        return COMM;
    }
    unsafe {
        length.write(bytes.len());
    }
    if cap < bytes.len() {
        return SMALL;
    }
    if !bytes.is_empty() {
        if out.is_null() {
            return COMM;
        }
        unsafe { output(out, bytes.len()) }.copy_from_slice(bytes);
    }
    OK
}
#[unsafe(no_mangle)]
extern "C" fn ck_pcsc_open(lun: u64) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if HOST.lock().unwrap().is_some() {
        return if valid(lun) { OK } else { MISSING };
    }
    if let Err(e) = initialize(None, "/tmp/lfs-root") {
        eprintln!("Rust PC/SC initialization: {e}");
        HOST.lock().unwrap().take();
        return COMM;
    }
    host(|h| {
        h.pcsc_lun = Some(lun);
        h.nfc = contactless();
    });
    // Flush mailbox/link state from any previous open before admission.
    unsafe {
        ck_hid_packet_reset();
        CTAPHID_Loop(0);
    }
    OK
}
#[unsafe(no_mangle)]
extern "C" fn ck_pcsc_close(lun: u64) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if !valid(lun) {
        return MISSING;
    }
    unsafe {
        ck_core_reset();
    }
    HOST.lock().unwrap().take();
    OK
}
#[unsafe(no_mangle)]
extern "C" fn ck_pcsc_present(lun: u64) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if valid(lun) { OK } else { MISSING }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_pcsc_capability(
    lun: u64,
    kind: u8,
    out: *mut u8,
    cap: usize,
    length: *mut usize,
) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if !valid(lun) {
        return MISSING;
    }
    let data = match kind {
        0 => {
            if host(|h| h.powered) {
                ATR
            } else {
                &[]
            }
        }
        1 | 2 | 3 | 4 => &[1], // one reader/slot, killable poll, serialized driver
        _ => return TAG,
    };
    unsafe { copy(data, out, cap, length) }
}
#[unsafe(no_mangle)]
extern "C" fn ck_pcsc_protocol(lun: u64, t1: u8) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if !valid(lun) {
        MISSING
    } else if t1 == 1 {
        OK
    } else {
        PROTOCOL
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_pcsc_power(
    lun: u64,
    action: u8,
    out: *mut u8,
    cap: usize,
    length: *mut usize,
) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if length.is_null() {
        return COMM;
    }
    unsafe {
        length.write(0);
    }
    if !valid(lun) {
        return MISSING;
    }
    if action > 2 {
        return UNSUPPORTED;
    }
    if action != 1 && (cap < ATR.len() || out.is_null()) {
        unsafe {
            length.write(ATR.len());
        }
        return SMALL;
    }
    // Power-down is a real authorization/session boundary, even if the reader
    // still reports that its virtual card is physically present. Slot resets
    // do not restart the CTAP power-on window; only MAGIC REBOOT does that.
    unsafe {
        ck_core_reset();
    }
    host(|h| {
        h.powered = false;
        h.led = false;
        h.gesture = Gesture::Idle;
    });
    if action == 1 {
        return OK;
    }
    let storage = match host(|h| h.storage.reopen()) {
        Ok(s) => s,
        Err(_) => return COMM,
    };
    host(|h| {
        h.storage = storage;
        h.nfc = contactless();
    });
    if unsafe { ck_core_install() } != 0 {
        return COMM;
    }
    host(|h| h.powered = true);
    unsafe { copy(ATR, out, cap, length) }
}
fn aggregate(request: &[u8]) -> bool {
    if request.len() >= 4 && request[0] == 0x80 {
        return true;
    }
    request.len() >= 7
        && request[0] == 0
        && request[4] == 0
        && (matches!(request[1], 1 | 2 | 3) || (request[1] == 0xa4 && request[2..4] != [4, 0]))
}
fn reboot() -> Result<(), ()> {
    unsafe {
        ck_core_reset();
    }
    let storage = host(|h| h.storage.reopen()).map_err(|_| ())?;
    host(|h| {
        h.storage = storage;
        h.boot = Instant::now();
        h.led = false;
        h.gesture = Gesture::Idle;
    });
    if unsafe { ck_core_install() } == 0 {
        Ok(())
    } else {
        Err(())
    }
}
fn test_control(request: &[u8]) -> Option<Result<Vec<u8>, ()>> {
    // Host-only legacy test INS. These never appear in firmware or APDU replay.
    // Parse through the shared decoder, so short and extended envelopes agree.
    let apdu = canokey_protocol::apdu::parse(request).ok()?;
    let h = apdu.info.header;
    if h.cla != 0 {
        return None;
    }
    if h.ins == 0xee && apdu.data == [0x12, 0x56, 0xab, 0xf0] {
        return Some(reboot().map(|()| vec![0x90, 0]));
    }
    if h.ins == 0xef {
        host(|host| host.storage.inject(h.p1, h.p2, apdu.data));
        return Some(Ok(vec![0x90, 0]));
    }
    None
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_pcsc_transmit(
    lun: u64,
    tx: *const u8,
    n: usize,
    rx: *mut u8,
    cap: usize,
    length: *mut usize,
) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if length.is_null() {
        return COMM;
    }
    unsafe {
        length.write(0);
    }
    if !valid(lun) {
        return MISSING;
    }
    if !host(|h| h.powered) {
        return COMM;
    }
    if tx.is_null() || rx.is_null() || n == 0 {
        return COMM;
    }
    if n > 1033 || cap < 2 {
        return SMALL;
    }
    let request = unsafe { input(tx, n) };
    host(|h| h.nfc = contactless());
    unsafe {
        ck_core_presence_sample();
    }
    if let Some(response) = test_control(request) {
        return match response {
            Ok(bytes) => unsafe { copy(&bytes, rx, cap, length) },
            Err(()) => COMM,
        };
    }
    let auto = host(|h| h.nfc) && aggregate(request);
    let mut pending = request;
    let mut written = 0usize;
    for _ in 0..256 {
        let response = exchange(pending);
        let data = response.len() - 2;
        let more = auto && response[data] == 0x61;
        let count = if more { data } else { response.len() };
        if count > cap - written {
            // No partial success and no response tail leaking into a later call.
            unsafe {
                ck_core_reset();
            }
            return SMALL;
        }
        unsafe { output(rx.add(written), count) }.copy_from_slice(&response[..count]);
        written += count;
        if !more {
            unsafe {
                length.write(written);
            }
            return OK;
        }
        pending = &[0, 0xc0, 0, 0, 0];
    }
    unsafe {
        ck_core_reset();
    }
    COMM
}
