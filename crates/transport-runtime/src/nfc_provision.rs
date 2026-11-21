// SPDX-License-Identifier: Apache-2.0
//! FM11NT EEPROM policy. Compare before programming to preserve endurance;
//! verify each write before accepting the chip's ISO-DEP configuration.
#![forbid(unsafe_code)]
use super::nfc_io::Chip;
use canokey_protocol::nfc::fsci;

// FM11NT082C v1.2 section 3.4.2 requires 250 us from CSN low to I2C traffic.
const CSN_WAKE_DELAY_MS: u16 = 1;
// Table 5-5 specifies tWR = 10 ms for I2C EEPROM writes.
const EEPROM_WRITE_DELAY_MS: u16 = 10;

// FM11NT082C v1.2 Figure 3-2 gives the I2C EEPROM byte addresses.
// Section 3.2.3 orders the factory identity as SN0..SN2, BCC0, SN3..SN6, BCC1.
const UID_BCC_ADDRESS: u16 = 0x0000;
const UID_BCC_BYTES: usize = 9;

const USER_CONFIG_ADDRESS: u16 = 0x0390;
const USER_CONFIG: [u8; 4] = {
    // Section 3.3.3.2, 0x0390: Vout_mode[7:6]=0x2 (supply on power-up),
    // demodu_enhancement[5]=0, irq_mode[4]=1 (active-low open drain),
    // RFU[3:1]=0, OP_MODE_SELECT[0]=1 (NC channel mode).
    let cfg0 = 0x91;
    // Section 3.3.3.3, 0x0391: rf_inventory_en[7]=1 (fast anticollision),
    // fdt_comp_en[6]=0, fdel[5:4]=0 (2/fc when enabled),
    // NFC_MODE[3:2]=0 (ISO/IEC 14443-4), RFU[1:0]=0.
    let cfg1 = 0x80;
    // Section 3.3.3.4, 0x0392: RFU[7:6]=0, arbitration_cfg[5:4]=0x2
    // (contact interface priority), ct_sleep_cfg[3:0]=0x1 (sleep after 1 ms).
    let cfg2 = 0x21;
    // Section 3.2.9, 0x0393: USER CFG CHK WORD is the complement of the XOR (0xcf).
    [cfg0, cfg1, cfg2, !(cfg0 ^ cfg1 ^ cfg2)]
};

// Figure 3-2 and Table 4-1 split ATS across 0x03b0..0x03b1 (TL, T0)
// and 0x03b4..0x03b6 (TA1, TB1, TC1). Keep VOUT_RES_CFG at 0x03b2,
// I2C Addr at 0x03b3 and DEMO_PAD_CFG at 0x03b7 intact.
const ATS_TL_T0_ADDRESS: u16 = 0x03b0;
const ATS_INTERFACE_ADDRESS: u16 = 0x03b4;
// ISO/IEC 14443-4 ATS coding. TL includes itself and excludes the RF CRC.
const ATS_LENGTH: u8 = 5;
// T0 b7/b6/b5 announce TC1/TB1/TA1. The low nibble holds FSCI
// (0x8 for 256 bytes, including PCB and RF CRC).
const ATS_INTERFACE_PRESENT: u8 = 0x70;
const FWI: u8 = 9;
const SFGI: u8 = 7;

// Figure 3-2 and section 3.6.1. ATQA 0x0044 (seven-byte UID) is stored low byte
// first, followed by SAK1=0x04 (UID cascades) and SAK2=0x20 (ISO-DEP),
// using the ISO/IEC 14443-3 Type A response coding.
const ATQA_SAK_ADDRESS: u16 = 0x03bc;
const ATQA_SAK: [u8; 4] = [0x44, 0x00, 0x04, 0x20];

// Figure 3-2 labels 0x03bb chk_crc8. The algorithm comes from the legacy
// CanoKey FM11NT driver (fm11_init/fm_crc8): UID/BCC then ATQA/SAK in
// EEPROM order, LSB first with reflected polynomial 0xb8 and no final XOR.
const IDENTITY_CRC_ADDRESS: u16 = 0x03bb;
const CRC8_POLYNOMIAL: u8 = 0xb8;
const CRC8_INITIAL: u8 = 0xff;

pub trait Provision: Chip {
    fn select(&mut self, active: bool);
    fn delay_ms(&mut self, milliseconds: u16);
}
fn ensure(chip: &mut impl Provision, address: u16, expected: &[u8]) -> bool {
    // The longest programmed fields are USER_CONFIG and ATQA_SAK.
    let mut current = [0x00; 4];
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
pub fn configure_for<const FSC: usize>(chip: &mut impl Provision) -> bool {
    let ats_tl_t0 = [ATS_LENGTH, ATS_INTERFACE_PRESENT | const { fsci(FSC) }];
    let ats_interface = [
        0x00,              // TA1: 106 kbit/s in both directions (chip manual section 4.4.1).
        (FWI << 4) | SFGI, // TB1: FWI[7:4] and SFGI[3:0].
        0x00,              // TC1: CID (b2) and NAD (b1) unsupported.
    ];
    chip.select(true);
    chip.delay_ms(CSN_WAKE_DELAY_MS);
    let ok = (|| {
        if !ensure(chip, USER_CONFIG_ADDRESS, &USER_CONFIG)
            || !ensure(chip, ATS_TL_T0_ADDRESS, &ats_tl_t0)
            || !ensure(chip, ATS_INTERFACE_ADDRESS, &ats_interface)
            || !ensure(chip, ATQA_SAK_ADDRESS, &ATQA_SAK)
        {
            return false;
        }
        let mut identity = [0x00; UID_BCC_BYTES + ATQA_SAK.len()];
        if !chip.read(UID_BCC_ADDRESS, &mut identity[..UID_BCC_BYTES]) {
            return false;
        }
        identity[UID_BCC_BYTES..].copy_from_slice(&ATQA_SAK);
        let mut crc = CRC8_INITIAL;
        for byte in identity {
            crc ^= byte;
            for _ in 0..8 {
                crc = (crc >> 1)
                    ^ if crc & 0x01 != 0x00 {
                        CRC8_POLYNOMIAL
                    } else {
                        0x00
                    };
            }
        }
        ensure(chip, IDENTITY_CRC_ADDRESS, &[crc])
    })();
    chip.select(false);
    ok
}
