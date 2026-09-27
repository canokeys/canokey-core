// SPDX-License-Identifier: Apache-2.0
//! FM11NT EEPROM policy. Compare before programming to preserve endurance;
//! verify each write before accepting the chip's ISO-DEP configuration.
#![forbid(unsafe_code)]
use super::nfc_io::Chip;
pub trait Provision: Chip {
    fn select(&mut self, active: bool);
    fn delay_ms(&mut self, milliseconds: u16);
}
fn ensure(chip: &mut impl Provision, address: u16, expected: &[u8]) -> bool {
    let mut current = [0; 7];
    let current = &mut current[..expected.len()];
    if !chip.read(address, current) {
        return false;
    }
    if current == expected {
        return true;
    }
    if !chip.write(address, expected) {
        return false;
    }
    chip.delay_ms(10);
    chip.read(address, current) && current == expected
}
pub fn configure(chip: &mut impl Provision) -> bool {
    chip.select(true);
    chip.delay_ms(1);
    let ok = (|| {
        const ATQA_SAK: [u8; 4] = [0x44, 0, 4, 0x20];
        if !ensure(chip, 0x0390, &[0x91, 0x80, 0x21, 0xcf])
            || !ensure(chip, 0x03b0, &[5, 0x72, 0xa0, 0x57, 0, 0x99, 0])
            || !ensure(chip, 0x03bc, &ATQA_SAK)
        {
            return false;
        }
        let mut identity = [0; 13];
        if !chip.read(0, &mut identity[..9]) {
            return false;
        }
        identity[9..].copy_from_slice(&ATQA_SAK);
        let mut crc = 0xff;
        for byte in identity {
            crc ^= byte;
            for _ in 0..8 {
                crc = (crc >> 1) ^ if crc & 1 != 0 { 0xb8 } else { 0 };
            }
        }
        ensure(chip, 0x03bb, &[crc])
    })();
    chip.select(false);
    ok
}
