// SPDX-License-Identifier: Apache-2.0
//! PC/SC slot/session policy. The Rust IFD adapter translates platform types and
//! constants only. Every entry touching CORE takes ENTRY, across host threads.
use super::*;
const OK: i32 = 0;
const COMM: i32 = 1;
const SMALL: i32 = 2;
const UNSUPPORTED: i32 = 3;
const MISSING: i32 = 4;
const PROTOCOL: i32 = 5;
const TAG: i32 = 6;
const ATR: &[u8] = canokey_protocol::ccid::ATR;
// Internal actions translated from IFD_POWER_* by the IFD adapter.
const POWER_UP: u8 = 0x00;
const POWER_DOWN: u8 = 0x01;
const POWER_RESET: u8 = 0x02;
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
pub(super) fn ck_pcsc_open(lun: u64) -> i32 {
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
        hid::poll::<HostProvider>();
    }
    OK
}
pub(super) fn ck_pcsc_close(lun: u64) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if !valid(lun) {
        return MISSING;
    }
    unsafe {
        core::reset::<HostProvider>();
    }
    HOST.lock().unwrap().take();
    OK
}
pub(super) fn ck_pcsc_present(lun: u64) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if valid(lun) { OK } else { MISSING }
}
pub(super) unsafe fn ck_pcsc_capability(
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
        // The IFD adapter maps kinds 1..=4 to simultaneous access,
        // slot count, killable polling and thread safety. Counts are one;
        // both boolean capabilities are true (Rust ENTRY serializes calls).
        1 | 2 | 3 | 4 => &[1],
        _ => return TAG,
    };
    unsafe { copy(data, out, cap, length) }
}
pub(super) fn ck_pcsc_protocol(lun: u64, t1: u8) -> i32 {
    let _entry = ENTRY.lock().unwrap();
    if !valid(lun) {
        MISSING
    } else if t1 == 1 {
        OK
    } else {
        PROTOCOL
    }
}
pub(super) unsafe fn ck_pcsc_power(
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
    if !matches!(action, POWER_UP | POWER_DOWN | POWER_RESET) {
        return UNSUPPORTED;
    }
    if action != POWER_DOWN && (cap < ATR.len() || out.is_null()) {
        unsafe {
            length.write(ATR.len());
        }
        return SMALL;
    }
    // As on USB CCID, slot power retains CTAP selection and session ownership,
    // but closes response chains and clears message fragments/workspace.
    // Other applet grants are revoked; device reset/close clears every session.
    unsafe {
        core::slot_power::<HostProvider>();
    }
    host(|h| {
        h.powered = false;
        h.led = false;
        h.gesture = Gesture::Idle;
    });
    if action == POWER_DOWN {
        return OK;
    }
    let storage = match host(|h| h.storage.reopen()) {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                core::reset::<HostProvider>();
            }
            return COMM;
        }
    };
    host(|h| {
        h.storage = storage;
        h.nfc = contactless();
    });
    host(|h| h.powered = true);
    unsafe { copy(ATR, out, cap, length) }
}
// Contactless FIDO clients receive one assembled reply. Other applets retain
// APDU-level 61xx paging so GET RESPONSE remains visible to the caller.
fn aggregate(request: &[u8]) -> bool {
    if request.len() >= 4 && request[0] == apdu_wire::CLA_FIDO {
        return true;
    }
    request.len() >= apdu_wire::EXTENDED_HEADER_BYTES
        && request[0] == 0
        && request[4] == 0
        && (matches!(
            request[1],
            apdu_wire::U2F_REGISTER | apdu_wire::U2F_AUTHENTICATE | apdu_wire::U2F_VERSION
        ) || (request[1] == apdu_wire::INS_SELECT
            && request[2..4] != [apdu_wire::SELECT_BY_NAME, 0x00]))
}
fn reboot() -> Result<(), ()> {
    unsafe {
        core::reset::<HostProvider>();
    }
    let storage = host(|h| h.storage.reopen()).map_err(|_| ())?;
    host(|h| {
        h.storage = storage;
        h.boot = Instant::now();
        h.led = false;
        h.gesture = Gesture::Idle;
    });
    if unsafe { core::install::<HostProvider>() } == 0 {
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
    // Test-only reboot cookie shared with legacy host clients; never a product command.
    if h.ins == 0xee && apdu.data == [0x12, 0x56, 0xab, 0xf0] {
        return Some(reboot().map(|()| vec![0x90, 0]));
    }
    if h.ins == 0xef {
        host(|host| host.storage.inject(h.p1, h.p2, apdu.data));
        return Some(Ok(vec![0x90, 0]));
    }
    None
}
pub(super) unsafe fn ck_pcsc_transmit(
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
    if n > canokey_protocol::ctaphid::CTAP_MAX_REQUEST + apdu_wire::EXTENDED_OVERHEAD_BYTES
        || cap < apdu_wire::STATUS_BYTES
    {
        return SMALL;
    }
    let request = unsafe { input(tx, n) };
    host(|h| h.nfc = contactless());
    presence_sample();
    if let Some(response) = test_control(request) {
        return match response {
            Ok(bytes) => unsafe { copy(&bytes, rx, cap, length) },
            Err(()) => COMM,
        };
    }
    let auto = host(|h| h.nfc) && aggregate(request);
    let mut pending = request;
    let mut written = 0usize;
    for _ in 0..apdu_wire::RESPONSE_CHAIN_LIMIT {
        let response = exchange(pending);
        let data = response.len() - 2;
        let more = auto && response[data] == apdu_wire::MORE_DATA_SW1;
        let count = if more { data } else { response.len() };
        if count > cap - written {
            // No partial success and no response tail leaking into a later call.
            unsafe {
                core::reset::<HostProvider>();
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
        pending = &apdu_wire::GET_RESPONSE;
    }
    unsafe {
        core::reset::<HostProvider>();
    }
    COMM
}
