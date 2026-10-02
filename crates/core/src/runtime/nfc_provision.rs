// SPDX-License-Identifier: Apache-2.0
//! FM11NT EEPROM policy. Compare before programming to preserve endurance;
//! verify each write before accepting the chip's ISO-DEP configuration.
#![forbid(unsafe_code)]
use super::nfc_io::Chip;
const EEPROM_WRITE_DELAY_MS: u16 = 10;
const USER_CONFIG_ADDRESS: u16 = 0x0390;
const ATS_ADDRESS: u16 = 0x03b0;
const IDENTITY_CHECKSUM: u16 = 0x03bb;
const ATQA_SAK_ADDRESS: u16 = 0x03bc;
const UID_BCC_BYTES: usize = 9;
// FM11NT reflected CRC-8 polynomial and initial accumulator for UID/ATQA/SAK.
const CRC8_POLYNOMIAL: u8 = 0xb8;
const CRC8_INITIAL: u8 = 0xff;
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
    chip.delay_ms(EEPROM_WRITE_DELAY_MS);
    chip.read(address, current) && current == expected
}
pub fn configure(chip: &mut impl Provision) -> bool {
    chip.select(true);
    chip.delay_ms(1);
    let ok = (|| {
        // ATQA=0044 (seven-byte UID), cascade SAK=04, final SAK=20 (ISO-DEP).
        const ATQA_SAK: [u8; 4] = [0x44, 0x00, 0x04, 0x20];
        // Board-qualified FM11NT RF and protocol EEPROM settings; byte order
        // follows consecutive chip addresses, not a host-endian integer.
        if !ensure(chip, USER_CONFIG_ADDRESS, &[0x91, 0x80, 0x21, 0xcf])
            // ATS: TL=05, T0=72, TA1=A0, TB1=57, TC1=00; the trailing
            // 99/00 are the retained FM11NT EEPROM configuration bytes.
            || !ensure(chip, ATS_ADDRESS, &[0x05, 0x72, 0xa0, 0x57, 0, 0x99, 0])
            || !ensure(chip, ATQA_SAK_ADDRESS, &ATQA_SAK)
        {
            return false;
        }
        let mut identity = [0; UID_BCC_BYTES + ATQA_SAK.len()];
        if !chip.read(0, &mut identity[..UID_BCC_BYTES]) {
            return false;
        }
        identity[UID_BCC_BYTES..].copy_from_slice(&ATQA_SAK);
        let mut crc = CRC8_INITIAL;
        for byte in identity {
            crc ^= byte;
            for _ in 0..8 {
                crc = (crc >> 1) ^ if crc & 1 != 0 { CRC8_POLYNOMIAL } else { 0 };
            }
        }
        ensure(chip, IDENTITY_CHECKSUM, &[crc])
    })();
    chip.select(false);
    ok
}
