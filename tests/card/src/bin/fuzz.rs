// SPDX-License-Identifier: Apache-2.0
#![no_main]
use canokey_ports::Record;
use canokey_test_card::Card;
use std::cell::RefCell;

// Framed corpus: tag, u16 little-endian payload length, then payload.
const APDU: u8 = 0x00;
const POWER_OFF: u8 = 0x01;
const STORAGE_FAULT: u8 = 0x02;
const RESET: u8 = 0x03;
const APDU_RAW: u8 = 0x04;
const FAIL_WRITE: u8 = 0x00;
const FAIL_READ: u8 = 0x01;
const MAX_APDU_BYTES: usize = 4096;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CHAINS: usize = 1024;
const SHORT_RESPONSE_BYTES: usize = 288;
// ISO 7816 GET RESPONSE, short Le=0 (256 bytes).
const GET_RESPONSE: &[u8] = &[0x00, 0xc0, 0x00, 0x00, 0x00];

thread_local! {
    // libFuzzer invokes inputs serially. State persists across inputs, matching
    // the previous harness; corpus events choose slot power or full reset.
    static CARD: RefCell<Card> = RefCell::new({
        assert!(unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } >= 0);
        let mut card = unsafe { Card::new() };
        assert!(card.install());
        card
    });
}
fn apdu(card: &mut Card, mut input: &[u8], drain: bool) {
    let mut buffer = [0; SHORT_RESPONSE_BYTES];
    let mut total = 0;
    for _ in 0..MAX_CHAINS {
        let Some(n) = card.exchange(input, &mut buffer).filter(|&n| n >= 2) else {
            return;
        };
        let end = n - 2;
        let status = u16::from_be_bytes([buffer[end], buffer[end + 1]]);
        total += end;
        if total > MAX_RESPONSE_BYTES || !drain || status & 0xff00 != 0x6100 {
            return;
        }
        input = GET_RESPONSE;
    }
}
libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let mut input = bytes;
    CARD.with_borrow_mut(|card| {
        while input.len() >= 3 {
            let tag = input[0];
            let n = u16::from_le_bytes([input[1], input[2]]) as usize;
            input = &input[3..];
            if n > input.len() {
                return;
            }
            let (payload, rest) = input.split_at(n);
            match tag {
                APDU | APDU_RAW => {
                    if n <= MAX_APDU_BYTES {
                        apdu(card, payload, tag == APDU);
                    }
                }
                POWER_OFF if n == 0 => card.slot_power(),
                RESET if n == 0 => card.reset(),
                STORAGE_FAULT if n == 2 => {
                    let record = Record::from_id(payload[0]);
                    match payload[1] {
                        FAIL_WRITE => card.records.fail_write = record,
                        FAIL_READ => card.records.fail_read = record,
                        _ => return,
                    }
                }
                _ => return,
            }
            input = rest;
        }
    });
});
