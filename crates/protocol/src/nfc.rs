// SPDX-License-Identifier: Apache-2.0
//! ISO-DEP frames delivered by FM11NT. The controller checks and retains CRC
//! bytes on receive and appends CRC on transmit. CID/NAD are not advertised.
#![forbid(unsafe_code)]
pub const FRAME_LIMIT: usize = 32;
pub const INF_LIMIT: usize = 29;
// ISO 14443-4 PCB fields; bit 0 is the alternating block number.
pub const PCB_NUMBER: u8 = 0x01;
pub const PCB_CHAIN_OR_NAK: u8 = 0x10;
pub const PCB_I: u8 = 0x02;
pub const PCB_I_NEXT: u8 = PCB_I | PCB_NUMBER;
pub const PCB_I_CHAIN: u8 = PCB_I | PCB_CHAIN_OR_NAK;
pub const PCB_I_CHAIN_NEXT: u8 = PCB_I_CHAIN | PCB_NUMBER;
pub const PCB_ACK: u8 = 0xa2;
pub const PCB_ACK_NEXT: u8 = PCB_ACK | PCB_NUMBER;
pub const PCB_NAK: u8 = 0xb2;
pub const PCB_NAK_NEXT: u8 = PCB_NAK | PCB_NUMBER;
pub const PCB_DESELECT: u8 = 0xc2;
pub const PCB_WTX: u8 = 0xf2;
pub const WTX_MULTIPLIER_MAX: u8 = 59;
// Host/controller policy: both the progress scheduler and due check use ms.
pub const WTX_INTERVAL_MS: u16 = 150;
// FM11NT register ABI. MAIN/FIFO/AUX IRQ form a contiguous read-to-clear triplet.
pub const FM_REG_MAIN_IRQ: u16 = 0xfff7;
pub const FM_IRQ_BYTES: usize = 3;
pub const FM_REG_FIFO_WORDCNT: u16 = 0xfff2;
pub const FM_REG_FIFO_ACCESS: u16 = 0xfff0;
pub const FM_REG_RF_TXEN: u16 = 0xfff4;
pub const FM_RF_TX_ENABLE: u8 = 0x55;
pub const FM_REG_RESET_SILENCE: u16 = 0xffe6;
pub const FM_SILENCE: u8 = 0x33;
pub const FM_UNSILENCE: u8 = 0xcc;
pub const FM_REG_MAIN_IRQ_MASK: u16 = 0xfffa;
pub const FM_MAIN_IRQ_MASK: u8 = 0x22;
pub const FM_AUX_ERRORS: u8 = 0x78;
pub const FM_FIFO_OVERFLOW: u8 = 0x04;
// AUX register (the third IRQ triplet byte): halt request from the frontend.
pub const FM_AUX_HALT: u8 = 0x04;
pub const FM_MAIN_ACTIVE: u8 = 0x40;
pub const FM_MAIN_RX_DONE: u8 = 0x10;
pub const FM_MAIN_ACTIVITY: u8 = 0x3f;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Block<'a> {
    Information {
        number: u8,
        chained: bool,
        bytes: &'a [u8],
    },
    Receive {
        number: u8,
        negative: bool,
    },
    Waiting(u8),
    Deselect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Prologue,
    Multiplier,
}
pub fn decode(frame: &[u8]) -> Result<Block<'_>, Error> {
    if !(3..=FRAME_LIMIT).contains(&frame.len()) {
        return Err(Error::Length);
    }
    let pcb = frame[0];
    let inf = &frame[1..frame.len() - 2];
    match pcb {
        PCB_I | PCB_I_NEXT | PCB_I_CHAIN | PCB_I_CHAIN_NEXT => Ok(Block::Information {
            number: pcb & PCB_NUMBER,
            chained: pcb & PCB_CHAIN_OR_NAK != 0,
            bytes: inf,
        }),
        PCB_ACK | PCB_ACK_NEXT | PCB_NAK | PCB_NAK_NEXT if inf.is_empty() => Ok(Block::Receive {
            number: pcb & PCB_NUMBER,
            negative: pcb & PCB_CHAIN_OR_NAK != 0,
        }),
        PCB_DESELECT if inf.is_empty() => Ok(Block::Deselect),
        PCB_WTX if inf.len() == 1 => {
            if !(1..=WTX_MULTIPLIER_MAX).contains(&inf[0]) {
                return Err(Error::Multiplier);
            }
            Ok(Block::Waiting(inf[0]))
        }
        PCB_ACK | PCB_ACK_NEXT | PCB_NAK | PCB_NAK_NEXT | PCB_DESELECT | PCB_WTX => {
            Err(Error::Length)
        }
        _ => Err(Error::Prologue),
    }
}
/// Packet bytes exclude CRC; the chip generates it. The last successful
/// information packet is retained by the runtime for exact retransmission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    bytes: [u8; 30],
    length: u8,
}
impl Packet {
    pub fn information(number: u8, chained: bool, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > INF_LIMIT {
            return Err(Error::Length);
        }
        let mut packet = Self::control(
            PCB_I | (number & PCB_NUMBER) | if chained { PCB_CHAIN_OR_NAK } else { 0 },
        );
        packet.bytes[1..1 + bytes.len()].copy_from_slice(bytes);
        packet.length += bytes.len() as u8;
        Ok(packet)
    }
    pub const fn acknowledgement(number: u8) -> Self {
        Self::control(PCB_ACK | (number & PCB_NUMBER))
    }
    pub const fn deselect() -> Self {
        Self::control(PCB_DESELECT)
    }
    pub fn waiting(multiplier: u8) -> Result<Self, Error> {
        if !(1..=WTX_MULTIPLIER_MAX).contains(&multiplier) {
            return Err(Error::Multiplier);
        }
        let mut packet = Self::control(PCB_WTX);
        packet.bytes[1] = multiplier;
        packet.length = 2;
        Ok(packet)
    }
    const fn control(pcb: u8) -> Self {
        let mut bytes = [0; 30];
        bytes[0] = pcb;
        Self { bytes, length: 1 }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
}
