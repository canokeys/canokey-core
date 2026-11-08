// SPDX-License-Identifier: Apache-2.0
//! Actual NFC facade, link and IRQ state with register and applet substitutes.
use super::*;
const RESPONSE_PAYLOAD: usize = 40;
// Empty-AID SELECT and GET RESPONSE exercise the shared short APDU buffer.
const SELECT: [u8; 5] = [0x00, 0xa4, 0x04, 0x00, 0x00];
// ISO-DEP I-block, SELECT body, and two CRC bytes ignored by the chip facade.
const COMMAND: [u8; 8] = [0x02, 0x00, 0xa4, 0x04, 0x00, 0x00, 0x00, 0x00];
// FIDO SELECT-by-name I-block followed by two chip-checked CRC bytes.
const FIDO_SELECT: [u8; 16] = [
    0x02, 0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01, 0x00, 0x00,
];
// Extended CTAP APDU with one payload byte and the next I-block sequence bit.
const FIDO_EXTENDED: [u8; 11] = [
    0x03, 0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00,
];
struct Stage {
    bytes: [u8; canokey_rust_core::config::CTAP_MAX_REQUEST],
    held: bool,
    writes: usize,
    closes: usize,
}
static mut STAGE: Stage = Stage {
    bytes: [0; canokey_rust_core::config::CTAP_MAX_REQUEST],
    held: false,
    writes: 0,
    closes: 0,
};
fn stage() -> &'static mut Stage {
    unsafe { &mut *core::ptr::addr_of_mut!(STAGE) }
}
pub(super) fn prepare(prefix: &[u8; 7]) -> Result<(), Rejection> {
    if prefix[..2] != [0x80, 0x10] {
        return Err(Rejection::Status(Sw::WRONG_LENGTH));
    }
    if !controller().fido {
        return Err(Rejection::Status(Sw::FILE_NOT_FOUND));
    }
    if prefix[2] & 0x7f != 0 || prefix[3] != 0 {
        return Err(Rejection::Status(Sw::WRONG_P1P2));
    }
    if usize::from(u16::from_be_bytes([prefix[5], prefix[6]])) > stage().bytes.len() {
        return Err(Rejection::TooLarge);
    }
    assert!(!stage().held);
    stage().held = true;
    Ok(())
}
pub(super) fn stage_write(offset: usize, bytes: &[u8]) -> bool {
    assert!(stage().held);
    stage().bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
    stage().writes += 1;
    true
}
pub(super) fn stage_read(offset: usize, out: &mut [u8]) -> bool {
    assert!(stage().held);
    out.copy_from_slice(&stage().bytes[offset..offset + out.len()]);
    true
}
pub(super) fn stage_close() {
    assert!(stage().held);
    stage().bytes.fill(0);
    stage().held = false;
    stage().closes += 1;
}
pub(super) unsafe fn dispatch<P: Provider>(request: &mut Request, buffer: *mut u8) -> Outcome {
    let mut backend = Stager::<P>(core::marker::PhantomData);
    let result = request.finish(
        unsafe { core::slice::from_raw_parts(buffer, apdu::SHORT_FRAME_BYTES) },
        &mut backend,
    );
    let mut input = std::vec![0; request.len()];
    if result.is_ok() {
        assert!(request.read(
            0,
            &mut input,
            unsafe { core::slice::from_raw_parts(buffer, apdu::SHORT_FRAME_BYTES) },
            &mut backend
        ));
    }
    let info = apdu::parse(&input).ok().map(|command| command.info);
    request.reset(&mut backend);
    match result {
        Err(rejection) => {
            let response: &[u8] = match rejection {
                Rejection::TooLarge => &[0x39, 0x90, 0],
                Rejection::Status(sw) => {
                    let bytes = sw.bytes();
                    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, 2) };
                    return Outcome {
                        length: 2,
                        info: None,
                        fido: false,
                    };
                }
            };
            unsafe { core::ptr::copy_nonoverlapping(response.as_ptr(), buffer, response.len()) };
            Outcome {
                length: response.len() as i32,
                info: None,
                fido: false,
            }
        }
        Ok(()) => {
            assert!(
                !stage().held,
                "PKE must be released before command execution"
            );
            let pointer = if input.len() <= apdu::SHORT_FRAME_BYTES {
                buffer as *const u8
            } else {
                input.as_ptr()
            };
            let length = unsafe {
                ck_core_exchange(
                    crate::transport::owners::OWNER_NFC,
                    pointer,
                    input.len(),
                    buffer,
                    apdu::SHORT_REPLY_BYTES,
                )
            };
            Outcome {
                length,
                info,
                fido: controller().fido,
            }
        }
    }
}
struct Controller {
    masked: u32,
    now: u32,
    flags: [u8; wire::FM_IRQ_BYTES],
    rx: [u8; wire::FRAME_LIMIT],
    rxlen: usize,
    tx: [u8; wire::FRAME_LIMIT],
    txlen: usize,
    calls: usize,
    resets: usize,
    sends: usize,
    resets_in_core: usize,
    reset_in_core: bool,
    waiting_in_core: bool,
    fido: bool,
    continuation: usize,
    response_total: usize,
    response_offset: usize,
    response_chunk: usize,
    executed_len: usize,
    get_response_les: std::vec::Vec<u32>,
    timer: Option<unsafe extern "C" fn()>,
}
impl Controller {
    const fn new() -> Self {
        Self {
            masked: 0,
            now: 0,
            flags: [0; wire::FM_IRQ_BYTES],
            rx: [0; wire::FRAME_LIMIT],
            rxlen: 0,
            tx: [0; wire::FRAME_LIMIT],
            txlen: 0,
            calls: 0,
            resets: 0,
            sends: 0,
            resets_in_core: 0,
            reset_in_core: false,
            waiting_in_core: false,
            fido: false,
            continuation: 0,
            response_total: RESPONSE_PAYLOAD * 2,
            response_offset: 0,
            response_chunk: RESPONSE_PAYLOAD,
            executed_len: 0,
            get_response_les: std::vec::Vec::new(),
            timer: None,
        }
    }
}
static mut CONTROLLER: Controller = Controller::new();
fn controller() -> &'static mut Controller {
    unsafe { &mut *core::ptr::addr_of_mut!(CONTROLLER) }
}
pub(crate) unsafe fn ck_nfc_io_lock() -> u32 {
    let c = controller();
    let prior = c.masked;
    c.masked = 1;
    prior
}
pub(crate) unsafe fn ck_nfc_io_unlock(prior: u32) {
    controller().masked = prior;
}
pub(crate) unsafe fn ck_nfc_io_select(_active: u8) {}
pub(crate) unsafe fn ck_nfc_io_delay(_milliseconds: u16) {}
pub(crate) unsafe fn ck_nfc_io_now() -> u32 {
    controller().now
}
pub(crate) unsafe fn ck_nfc_io_schedule(
    callback: Option<unsafe extern "C" fn()>,
    milliseconds: u16,
) {
    assert_ne!(controller().masked, 0);
    assert!(callback.is_none() || milliseconds == wire::WTX_INTERVAL_MS);
    controller().timer = callback;
}
pub(crate) unsafe fn ck_nfc_io_read(address: u16, out: *mut u8, length: u8) -> i32 {
    let out = unsafe { core::slice::from_raw_parts_mut(out, usize::from(length)) };
    let c = controller();
    assert_ne!(c.masked, 0);
    match address {
        wire::FM_REG_MAIN_IRQ => {
            out.copy_from_slice(&c.flags);
            c.flags.fill(0);
        }
        wire::FM_REG_FIFO_WORDCNT => {
            assert_eq!(out.len(), 1);
            out[0] = c.rxlen as u8;
        }
        wire::FM_REG_FIFO_ACCESS => out.copy_from_slice(&c.rx[..c.rxlen]),
        _ => panic!("unexpected NFC register {address:#x}"),
    }
    0
}
pub(crate) unsafe fn ck_nfc_io_write(address: u16, bytes: *const u8, length: u8) -> i32 {
    let bytes = unsafe { core::slice::from_raw_parts(bytes, usize::from(length)) };
    let c = controller();
    assert_ne!(c.masked, 0);
    match address {
        wire::FM_REG_FIFO_ACCESS => {
            assert!(bytes.len() <= wire::FRAME_LIMIT - 2);
            c.tx[..bytes.len()].copy_from_slice(bytes);
            c.txlen = bytes.len();
        }
        wire::FM_REG_RF_TXEN => {
            assert_eq!(bytes, &[wire::FM_RF_TX_ENABLE]);
            c.sends += 1;
        }
        wire::FM_REG_RESET_SILENCE | wire::FM_REG_MAIN_IRQ_MASK => {}
        _ => panic!("unexpected NFC register {address:#x}"),
    }
    0
}
pub(crate) unsafe fn deinit() {
    assert_eq!(controller().masked, 0);
}
pub(crate) unsafe fn ck_core_reset() {
    assert_eq!(controller().masked, 0);
    controller().resets += 1;
}
fn frame(bytes: &[u8]) {
    let c = controller();
    c.rx[..bytes.len()].copy_from_slice(bytes);
    c.rxlen = bytes.len();
    c.flags[0] = wire::FM_MAIN_RX_DONE;
    unsafe { nfc_handler() };
}
fn activate() {
    controller().flags[0] = wire::FM_MAIN_ACTIVE;
    unsafe { nfc_handler() };
}
pub(crate) unsafe fn ck_core_exchange(
    owner: u8,
    input: *const u8,
    length: usize,
    out: *mut u8,
    capacity: usize,
) -> i32 {
    assert_eq!(controller().masked, 0);
    assert_eq!(owner, crate::transport::owners::OWNER_NFC);
    assert_eq!(out, crate::transport::ccid::ck_ccid_response_buffer());
    assert_eq!(capacity, apdu::SHORT_REPLY_BYTES);
    controller().calls += 1;
    let input = unsafe { core::slice::from_raw_parts(input, length) };
    // Read all input before mutating the aliased shared response allocation.
    if controller().fido {
        assert_ne!(unsafe { ck_nfc_progress() }, 0);
        if input[1] == apdu::INS_SELECT {
            assert_eq!(length, FIDO_SELECT.len() - 3);
            unsafe {
                out.write(0x90);
                out.add(1).write(0x00);
            }
            return 2;
        }
        let command = apdu::parse(input).unwrap();
        let le = command.info.le.unwrap_or(65536) as usize;
        if input[1] == 0x10 {
            assert_eq!(input[4], 0);
            controller().continuation = 0;
            controller().response_offset = 0;
            controller().executed_len = input.len();
        } else {
            assert_eq!(&input[..4], &apdu::GET_RESPONSE[..4]);
            controller().continuation += 1;
            controller().get_response_les.push(le as u32);
        }
        let c = controller();
        let n = (c.response_total - c.response_offset)
            .min(c.response_chunk)
            .min(le);
        for i in 0..n {
            unsafe { out.add(i).write((c.response_offset + i) as u8) };
        }
        c.response_offset += n;
        unsafe {
            out.add(n).write(if c.response_offset < c.response_total {
                0x61
            } else {
                0x90
            });
            out.add(n + 1).write(0);
        }
        return (n + 2) as i32;
    } else {
        assert_eq!(
            input,
            if input.as_ptr() == out {
                &SELECT
            } else {
                &apdu::GET_RESPONSE
            }
        );
        assert_ne!(unsafe { ck_nfc_progress() }, 0);
        if controller().waiting_in_core {
            controller().now += u32::from(wire::WTX_INTERVAL_MS);
            let callback = controller().timer.take().unwrap();
            unsafe { callback() };
            assert_eq!(&controller().tx[..controller().txlen], &[wire::PCB_WTX, 1]);
        }
        if controller().reset_in_core {
            controller().resets_in_core = controller().resets;
            activate();
            assert_eq!(unsafe { ck_nfc_progress() }, 0);
            assert_eq!(controller().resets, controller().resets_in_core);
        }
    }
    for i in 0..RESPONSE_PAYLOAD {
        unsafe { out.add(i).write(i as u8) };
    }
    unsafe {
        out.add(RESPONSE_PAYLOAD).write(0x90);
        out.add(RESPONSE_PAYLOAD + 1).write(0);
    }
    (RESPONSE_PAYLOAD + 2) as i32
}
fn poll() {
    unsafe { super::poll::<crate::platform::Native>() };
}
#[test]
fn nfc_link_chaining_wtx_reset_and_fido_aggregation() {
    let _guard = crate::TRANSPORT_TEST_LOCK.lock().unwrap();
    *controller() = Controller::new();
    unsafe { init::<crate::platform::Native>() };
    assert_ne!(unsafe { is_nfc() }, 0);
    assert_eq!(controller().resets, 1);
    frame(&COMMAND);
    poll();
    assert_eq!(controller().calls, 1);
    assert_eq!(controller().sends, 0);
    poll();
    assert_eq!(controller().sends, 1);
    assert_eq!(controller().txlen, 30);
    assert_eq!(controller().tx[0], 0x12);
    for i in 0..29 {
        assert_eq!(controller().tx[i + 1], i as u8);
    }
    // R-block with the current sequence requests the same chained reply again.
    frame(&[0xa2, 0, 0]);
    poll();
    assert_eq!(controller().sends, 2);
    assert_eq!(controller().tx[0], 0x12);
    assert_eq!(controller().calls, 1);
    frame(&[0xa3, 0, 0]);
    poll();
    assert_eq!(controller().sends, 3);
    assert_eq!(controller().txlen, 14);
    assert_eq!(controller().tx[0], 3);
    assert_eq!(&controller().tx[12..14], &[0x90, 0]);
    controller().now += 1000;
    poll();
    assert_eq!(controller().resets, 1);
    activate();
    poll();
    assert_eq!(controller().resets, 2);
    controller().waiting_in_core = true;
    frame(&COMMAND);
    poll();
    let sent = controller().sends;
    poll();
    assert_eq!(controller().sends, sent);
    // WTX echo releases the reply withheld during applet execution.
    frame(&[wire::PCB_WTX, 1, 0, 0]);
    poll();
    assert_eq!(controller().sends, sent + 1);
    assert_eq!(controller().tx[0], 0x12);
    controller().waiting_in_core = false;
    activate();
    poll();
    controller().reset_in_core = true;
    frame(&COMMAND);
    poll();
    let sent = controller().sends;
    assert_eq!(controller().resets, controller().resets_in_core);
    poll();
    assert_eq!(controller().resets, controller().resets_in_core + 1);
    assert_eq!(controller().sends, sent);
    controller().reset_in_core = false;
    activate();
    frame(&COMMAND);
    poll();
    let calls = controller().calls;
    poll();
    assert_eq!(controller().calls, calls + 1);
    poll();
    assert_eq!(controller().masked, 0);
    activate();
    poll();
    controller().fido = true;
    frame(&FIDO_SELECT);
    poll();
    poll();
    assert_eq!(controller().txlen, 3);
    assert_eq!(controller().tx[1], 0x90);
    frame(&FIDO_EXTENDED);
    poll();
    poll();
    let mut collected = [0; RESPONSE_PAYLOAD * 2 + 2];
    let mut total = 0;
    for blocks in 0..8 {
        let c = controller();
        let n = c.txlen - 1;
        collected[total..total + n].copy_from_slice(&c.tx[1..c.txlen]);
        total += n;
        if c.tx[0] & 0x10 == 0 {
            break;
        }
        assert!(blocks < 7);
        let sequence = (c.tx[0] ^ 1) & 1;
        frame(&[0xa2 | sequence, 0, 0]);
        poll();
        if controller().continuation == 1 && total == RESPONSE_PAYLOAD {
            poll();
        }
    }
    assert_eq!(total, collected.len());
    assert_eq!(controller().continuation, 1);
    for (i, byte) in collected[..RESPONSE_PAYLOAD * 2].iter().enumerate() {
        assert_eq!(*byte, i as u8);
    }
    assert_eq!(&collected[RESPONSE_PAYLOAD * 2..], &[0x90, 0]);
    controller().fido = false;
    activate();
    poll();
    controller().waiting_in_core = true;
    frame(&COMMAND);
    poll();
    let sent = controller().sends;
    let resets = controller().resets;
    controller().now += 200;
    poll();
    assert_eq!(controller().resets, resets + 1);
    assert_eq!(controller().sends, sent);
    assert_eq!(unsafe { ck_nfc_progress() }, 0);
    assert_eq!(controller().masked, 0);
    // Release the mode latch so the serialized USB fixture can run afterwards.
    unsafe { ck_nfc_set_mode(0) };
}

// Drive actual facade I-blocks and ACKs; no direct call to dispatch/execute.
fn exchange_blocks(command: &[u8], mut number: u8, repeat: bool) -> (std::vec::Vec<u8>, u8) {
    let parts = command.chunks(wire::INF_LIMIT);
    let count = parts.len();
    for (index, bytes) in parts.enumerate() {
        let mut packet = std::vec![0x02 | number | if index + 1 < count { 0x10 } else { 0 }];
        packet.extend_from_slice(bytes);
        packet.extend_from_slice(&[0, 0]);
        frame(&packet);
        poll();
        if index + 1 < count {
            if repeat {
                let writes = stage().writes;
                frame(&packet);
                poll();
                assert_eq!(stage().writes, writes);
            }
            number ^= 1;
        }
    }
    poll();
    let mut result = std::vec::Vec::new();
    for _ in 0..3000 {
        let c = controller();
        result.extend_from_slice(&c.tx[1..c.txlen]);
        number = (c.tx[0] ^ 1) & 1;
        if c.tx[0] & 0x10 == 0 {
            return (result, number);
        }
        let sent = c.sends;
        frame(&[0xa2 | number, 0, 0]);
        poll();
        if controller().sends == sent {
            poll(); // Internal GET RESPONSE computed, then released to RF.
        }
        assert_eq!(controller().sends, sent + 1);
    }
    panic!("NFC response did not terminate");
}

#[test]
fn large_requests_finite_le_remainder_and_staged_reset() {
    let _guard = crate::TRANSPORT_TEST_LOCK.lock().unwrap();
    for le in [
        None,
        Some(1u32),
        Some(255),
        Some(256),
        Some(257),
        Some(65535),
        Some(65536),
    ] {
        *controller() = Controller::new();
        unsafe { init::<crate::platform::Native>() };
        controller().fido = true;
        controller().response_total = 700;
        controller().response_chunk = 256;
        let mut command = std::vec![0x80, 0x10, 0, 0, 0, 0x03, 0x00];
        command.resize(7 + 768, 0x5a);
        if let Some(limit) = le {
            command.extend_from_slice(&(limit as u16).to_be_bytes());
        }
        let closed = stage().closes;
        let (result, number) = exchange_blocks(&command, 0, true);
        let emitted = le.unwrap_or(65536).min(700) as usize;
        assert_eq!(controller().executed_len, command.len());
        assert_eq!(stage().closes, closed + 1);
        assert!(!stage().held);
        assert!(stage().bytes.iter().all(|byte| *byte == 0));
        assert_eq!(result.len(), emitted + 2);
        assert_eq!(
            &result[emitted..],
            if emitted == 700 {
                &[0x90, 0]
            } else {
                &[0x61, 0]
            }
        );
        for (index, byte) in result[..emitted].iter().enumerate() {
            assert_eq!(*byte, index as u8);
        }
        if le == Some(257) {
            assert_eq!(controller().get_response_les, [1]);
        }
        if emitted < 700 {
            // Finite Le must preserve pending bytes for a reader's continuation.
            let (remainder, _) = exchange_blocks(&apdu::GET_RESPONSE, number, false);
            let n = (700 - emitted).min(256);
            assert_eq!(remainder.len(), n + 2);
            assert_eq!(remainder[0], emitted as u8);
        }
        unsafe { ck_nfc_set_mode(0) };
    }
    *controller() = Controller::new();
    unsafe { init::<crate::platform::Native>() };
    controller().fido = true;
    let mut packet = std::vec![0x12, 0x80, 0x10, 0, 0, 0, 0x03, 0x00];
    packet.extend_from_slice(&[0x5a; 20]);
    packet.extend_from_slice(&[0, 0]);
    frame(&packet);
    poll();
    assert!(stage().held);
    let closes = stage().closes;
    activate();
    poll();
    assert!(!stage().held);
    assert_eq!(stage().closes, closes + 1);
    assert!(stage().bytes.iter().all(|byte| *byte == 0));
    unsafe { ck_nfc_set_mode(0) };
}
